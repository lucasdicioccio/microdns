{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}

-- TODO:
-- turned HashedPart in some nonces to limit replay risks
module MicroDNS.DynamicRegistration where

import Control.Monad.IO.Class (liftIO)
import qualified Crypto.Hash.SHA256 as HMAC256
import Data.Aeson (FromJSON, ToJSON)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as C8
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.IP as IP
import qualified Data.List as List
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import GHC.Generics (Generic)
import Net.IPv4 as IPv4
import Net.IPv6 as IPv6
import qualified Network.DNS as DNS
import Network.Socket (SockAddr)
import Prod.Background as Background
import Prod.Tracer (Tracer (..), contramap)
import qualified Prod.Tracer as Tracer
import qualified Prometheus as Prometheus
import Servant
import Servant.Server

import MicroDNS.Handler (Apex (..), apexFromText)

type Api =
    AutoRegisterApi
        :<|> RegisterTextApi
        :<|> RegisterAApi
        :<|> RegisterAAAAApi
        :<|> ListRegistrationsApi

type DNSLeafName = Text

type AutoRegisterApi =
    Summary "registers a unique A record"
        :> "register"
        :> "auto"
        :> Capture "dns-leaf" DNSLeafName
        :> QueryParam "apex" Text
        :> RemoteHost
        :> Header "x-forwarded-for" Text
        :> Header "x-microdns-hmac" ChallengeAttempt
        :> Post '[JSON] AutoRegistrationResult

type RegisterTextApi =
    Summary "registers a TXT (e.g., for an ACME challenge)"
        :> "register"
        :> "txt"
        :> Capture "dns-leaf" DNSLeafName
        :> Capture "token" Text
        :> QueryParam "apex" Text
        :> Header "x-microdns-hmac" ChallengeAttempt
        :> Post '[JSON] (DNSLeafName, Text)

type RegisterAApi =
    Summary "registers a A"
        :> "register"
        :> "a"
        :> Capture "dns-leaf" DNSLeafName
        :> Capture "token" Text
        :> QueryParam "apex" Text
        :> Header "x-microdns-hmac" ChallengeAttempt
        :> Post '[JSON] (DNSLeafName, Text)

type RegisterAAAAApi =
    Summary "registers a AAAA"
        :> "register"
        :> "aaaa"
        :> Capture "dns-leaf" DNSLeafName
        :> Capture "token" Text
        :> QueryParam "apex" Text
        :> Header "x-microdns-hmac" ChallengeAttempt
        :> Post '[JSON] (DNSLeafName, Text)

type ListRegistrationsApi =
    Summary "list registrations"
        :> "registrations"
        :> Header "x-microdns-hmac" ChallengeAttempt
        :> Get '[JSON] Registrations

type ChallengeAttempt = Text

data AutoRegistrationResult
    = AutoRegistrationResult
    { registeredLeaf :: DNSLeafName
    , registeredIP :: Text
    }
    deriving (Show, Generic)
instance ToJSON AutoRegistrationResult

data RegistrationFailedReason
    = AuthError
    | ProxiedError
    | IPLookupError
    | IPParsingError
    deriving (Show)

data Registrations
    = Registrations
    { registrations :: [String]
    }
    deriving (Show, Generic)
instance ToJSON Registrations

data Trace
    = RegistrationSuccess DNS.ResourceRecord
    | RegistrationFailed RegistrationFailedReason
    deriving (Show)

data Counters
    = Counters
    { cnt_registrations :: Prometheus.Vector Text Prometheus.Counter
    , cnt_records :: Prometheus.Gauge
    }

initCounters :: IO Counters
initCounters =
    Counters
        <$> Prometheus.register
            ( Prometheus.vector
                ("status")
                (Prometheus.counter (Prometheus.Info "dyn_registrations" "number of DNS registrations"))
            )
        <*> Prometheus.register
            (Prometheus.gauge (Prometheus.Info "dyn_records" "number of DNS records"))

type SharedSecret = ByteString

data Runtime = Runtime
    { dnsApex :: Apex
    , sharedHmacSecret :: SharedSecret
    , counters :: Counters
    , rrs :: IORef [DNS.ResourceRecord]
    , tracer :: Tracer IO Trace
    , background :: BackgroundVal ()
    }

initRuntime :: Tracer IO Trace -> SharedSecret -> Apex -> IO Runtime
initRuntime tracer secret apex = do
    counters <- initCounters
    rrs <- newIORef []
    let updateCounters = Prometheus.setGauge (cnt_records counters) . fromIntegral . length =<< readIORef rrs
    bkg <- backgroundLoop Tracer.silent () updateCounters 5000000
    pure $ Runtime apex secret counters rrs tracer bkg

readRRs :: Runtime -> IO [DNS.ResourceRecord]
readRRs = readIORef . rrs

addRRa :: ActionAuthorized -> Runtime -> Apex -> DNSLeafName -> IP.IP -> IO DNS.ResourceRecord
addRRa _ rt apex leaf val = do
    atomicModifyIORef' (rrs rt) (\xs -> (insertRR newRecord xs, ()))
    pure newRecord
  where
    fqdn :: ByteString
    fqdn = mconcat [Text.encodeUtf8 leaf, ".", getApex apex]

    newRecord :: DNS.ResourceRecord
    newRecord = case val of
        IP.IPv4 val -> DNS.ResourceRecord fqdn DNS.A DNS.classIN 300 $ DNS.RD_A val
        IP.IPv6 val -> DNS.ResourceRecord fqdn DNS.AAAA DNS.classIN 300 $ DNS.RD_AAAA val

insertRR :: DNS.ResourceRecord -> [DNS.ResourceRecord] -> [DNS.ResourceRecord]
insertRR x xs = x : List.filter (otherFqdn x) xs

otherFqdn :: DNS.ResourceRecord -> DNS.ResourceRecord -> Bool
otherFqdn
    (DNS.ResourceRecord qdn2 _ _ _ _)
    (DNS.ResourceRecord qdn1 _ _ _ _) = qdn1 /= qdn2

addText :: ActionAuthorized -> Runtime -> Apex -> DNSLeafName -> Text -> IO DNS.ResourceRecord
addText _ rt apex leaf val = do
    atomicModifyIORef' (rrs rt) (\xs -> (insertRR newRecord xs, ()))
    pure newRecord
  where
    fqdn :: ByteString
    fqdn = mconcat [Text.encodeUtf8 leaf, ".", getApex apex]

    newRecord :: DNS.ResourceRecord
    newRecord =
        DNS.ResourceRecord fqdn DNS.TXT DNS.classIN 300 $ DNS.RD_TXT $ Text.encodeUtf8 val

handleDynamicRegistration :: Runtime -> Server Api
handleDynamicRegistration runtime =
    handleAutoRegister runtime
        :<|> handleTextRegister runtime
        :<|> handleARegister runtime
        :<|> handleAAAARegister runtime
        :<|> handleListRegistrations runtime

handleAutoRegister :: Runtime -> DNSLeafName -> Maybe Text -> SockAddr -> Maybe Text -> Maybe ChallengeAttempt -> Handler AutoRegistrationResult
handleAutoRegister rt _ _ _ (Just _) _ = do
    liftIO $ do
        Prometheus.withLabel (cnt_registrations $ counters rt) "error" Prometheus.incCounter
        runTracer (tracer rt) $ RegistrationFailed ProxiedError
    throwError err400
handleAutoRegister rt _ _ _ _ Nothing = do
    liftIO $ do
        Prometheus.withLabel (cnt_registrations $ counters rt) "error" Prometheus.incCounter
        runTracer (tracer rt) $ RegistrationFailed AuthError
    throwError err403
handleAutoRegister rt dnsleaf apex sockaddr Nothing (Just hmac) = do
    let hashedpart = (apex, dnsleaf)
    let auth = verifyHmac rt hashedpart hmac
    let ipport = IP.fromSockAddr sockaddr
    case auth of
        Nothing -> do
            liftIO $ do
                Prometheus.withLabel (cnt_registrations $ counters rt) "auth-error" Prometheus.incCounter
                runTracer (tracer rt) $ RegistrationFailed AuthError
            throwError err403
        Just success -> do
            case ipport of
                Nothing -> do
                    liftIO $ do
                        Prometheus.withLabel (cnt_registrations $ counters rt) "error" Prometheus.incCounter
                        runTracer (tracer rt) $ RegistrationFailed IPLookupError
                    throwError err500
                Just (ip, _) -> liftIO $ do
                    rr <- addRRa success rt (maybe (dnsApex rt) apexFromText apex) dnsleaf ip
                    runTracer (tracer rt) $ RegistrationSuccess rr
                    Prometheus.withLabel (cnt_registrations $ counters rt) "success" Prometheus.incCounter
                    pure $ AutoRegistrationResult dnsleaf (Text.pack $ show ip)

handleTextRegister :: Runtime -> DNSLeafName -> Text -> Maybe Text -> Maybe ChallengeAttempt -> Handler (DNSLeafName, Text)
handleTextRegister rt _ _ _ Nothing = do
    liftIO $ do
        Prometheus.withLabel (cnt_registrations $ counters rt) "auth-error" Prometheus.incCounter
        runTracer (tracer rt) $ RegistrationFailed AuthError
    throwError err403
handleTextRegister rt dnsleaf textval apex (Just hmac) = do
    let hashedpart = (apex, dnsleaf)
    let auth = verifyHmac rt hashedpart hmac
    case auth of
        Nothing -> do
            liftIO $ do
                Prometheus.withLabel (cnt_registrations $ counters rt) "auth-error" Prometheus.incCounter
                runTracer (tracer rt) $ RegistrationFailed AuthError
            throwError err403
        Just success -> liftIO $ do
            rr <- addText success rt (maybe (dnsApex rt) apexFromText apex) dnsleaf textval
            runTracer (tracer rt) $ RegistrationSuccess rr
            pure (dnsleaf, textval)

handleARegister :: Runtime -> DNSLeafName -> Text -> Maybe Text -> Maybe ChallengeAttempt -> Handler (DNSLeafName, Text)
handleARegister rt _ _ _ Nothing = do
    liftIO $ do
        Prometheus.withLabel (cnt_registrations $ counters rt) "auth-error" Prometheus.incCounter
        runTracer (tracer rt) $ RegistrationFailed AuthError
    throwError err403
handleARegister rt dnsleaf textval apex (Just hmac) = do
    let hashedpart = (apex, dnsleaf)
    let auth = verifyHmac rt hashedpart hmac
    case auth of
        Nothing -> do
            liftIO $ do
                Prometheus.withLabel (cnt_registrations $ counters rt) "auth-error" Prometheus.incCounter
                runTracer (tracer rt) $ RegistrationFailed AuthError
            throwError err403
        Just success -> do
            let ipv4 = IPv4.decode textval
            case ipv4 of
                Nothing -> do
                    liftIO $ do
                        Prometheus.withLabel (cnt_registrations $ counters rt) "error" Prometheus.incCounter
                        runTracer (tracer rt) $ RegistrationFailed IPParsingError
                    throwError err400
                Just ip -> liftIO $ do
                    rr <- addRRa success rt (maybe (dnsApex rt) apexFromText apex) dnsleaf (IP.IPv4 $ IP.fromHostAddress $ IPv4.getIPv4 ip)
                    runTracer (tracer rt) $ RegistrationSuccess rr
                    pure (dnsleaf, textval)

handleAAAARegister :: Runtime -> DNSLeafName -> Text -> Maybe Text -> Maybe ChallengeAttempt -> Handler (DNSLeafName, Text)
handleAAAARegister rt _ _ _ Nothing = do
    liftIO $ do
        Prometheus.withLabel (cnt_registrations $ counters rt) "auth-error" Prometheus.incCounter
        runTracer (tracer rt) $ RegistrationFailed AuthError
    throwError err403
handleAAAARegister rt dnsleaf textval apex (Just hmac) = do
    let hashedpart = (apex, dnsleaf)
    let auth = verifyHmac rt hashedpart hmac
    case auth of
        Nothing -> do
            liftIO $ do
                Prometheus.withLabel (cnt_registrations $ counters rt) "auth-error" Prometheus.incCounter
                runTracer (tracer rt) $ RegistrationFailed AuthError
            throwError err403
        Just success -> do
            let ipv6 = IPv6.decode textval
            case ipv6 of
                Nothing -> do
                    liftIO $ do
                        Prometheus.withLabel (cnt_registrations $ counters rt) "error" Prometheus.incCounter
                        runTracer (tracer rt) $ RegistrationFailed IPParsingError
                    throwError err400
                Just ip -> liftIO $ do
                    rr <- addRRa success rt (maybe (dnsApex rt) apexFromText apex) dnsleaf (IP.IPv6 $ IP.fromHostAddress6 $ IPv6.toWord32s ip)
                    runTracer (tracer rt) $ RegistrationSuccess rr
                    pure (dnsleaf, textval)

handleListRegistrations :: Runtime -> Maybe ChallengeAttempt -> Handler Registrations
handleListRegistrations rt _ = do
    rrs <- liftIO $ readRRs rt
    pure $ Registrations $ map show rrs

-- (apex?, txt)
type HashedPart = (Maybe Text, Text)

data ActionAuthorized = ActionAuthorized

verifyHmac :: Runtime -> HashedPart -> ChallengeAttempt -> Maybe ActionAuthorized
verifyHmac rt (apex, txt) attempt =
    if attempt == expected
        then Just ActionAuthorized
        else Nothing
  where
    hashedStr :: ByteString
    hashedStr = mconcat [maybe "" Text.encodeUtf8 apex, Text.encodeUtf8 txt]
    hmac = HMAC256.hmac (sharedHmacSecret rt) hashedStr
    expected = Text.decodeUtf8 $ Base16.encode $ hmac
