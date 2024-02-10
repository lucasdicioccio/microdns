{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
--TODO:
-- turned HashedPart in some nonces to limit replay risks
module MicroDNS.DynamicRegistration where

import GHC.Generics(Generic)
import Control.Monad.IO.Class (liftIO)
import qualified Network.DNS as DNS
import Data.Aeson (FromJSON, ToJSON)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString as ByteString
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.List as List
import Data.IORef (IORef, newIORef, readIORef, atomicModifyIORef')
import Network.Socket (SockAddr) 
import Data.IP as IP
import Servant
import Servant.Server
import Prod.Tracer (Tracer(..), contramap)
import qualified Prod.Tracer as Tracer
import Prod.Background as Background
import qualified Prometheus as Prometheus
import qualified Crypto.Hash.SHA256 as HMAC256

type Apex = ByteString

type Api = AutoRegisterApi
  :<|> RegisterTextApi
  :<|> ListRegistrationsApi

type DNSLeafName = Text

type AutoRegisterApi =
  Summary "registers a unique A record"
    :> "register"
    :> "auto"
    :> Capture "dns-leaf" DNSLeafName
    :> RemoteHost
    :> Header "x-forwarded-for" Text
    :> Header "x-microdns-hmac" ChallengeAttempt
    :> Post '[JSON] AutoRegistrationResult

type RegisterTextApi =
  Summary "registers a text (e.g., for an ACME challenge)"
    :> "register"
    :> "txt"
    :> Capture "dns-leaf" DNSLeafName
    :> Capture "token" Text
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
          (Prometheus.vector ("status")
            (Prometheus.counter (Prometheus.Info "dyn_registrations" "number of DNS registrations")))
    <*> Prometheus.register
          (Prometheus.gauge (Prometheus.Info "dyn_records" "number of DNS records"))

type SharedSecret = ByteString

data Runtime = Runtime {
    dnsApex :: Apex
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

addRRa :: ActionAuthorized -> Runtime -> DNSLeafName -> IP.IP -> IO DNS.ResourceRecord
addRRa _ rt leaf val = do
    atomicModifyIORef' (rrs rt) (\xs -> (insertRR xs, ()))
    pure newRecord
  where
    fqdn :: ByteString
    fqdn = mconcat [Text.encodeUtf8 leaf, ".",  dnsApex rt]

    newRecord :: DNS.ResourceRecord
    newRecord = case val of
      IP.IPv4 val -> DNS.ResourceRecord fqdn DNS.A DNS.classIN 300 $ DNS.RD_A val
      IP.IPv6 val -> DNS.ResourceRecord fqdn DNS.AAAA DNS.classIN 300 $ DNS.RD_AAAA val

    insertRR :: [DNS.ResourceRecord] -> [DNS.ResourceRecord]
    insertRR xs = newRecord : List.filter otherFqdn xs

    otherFqdn :: DNS.ResourceRecord -> Bool
    otherFqdn (DNS.ResourceRecord qdn _ _ _ _) = fqdn /= qdn

addText :: ActionAuthorized -> Runtime -> DNSLeafName -> Text -> IO DNS.ResourceRecord
addText _ rt leaf val = do
    atomicModifyIORef' (rrs rt) (\xs -> (insertRR xs, ()))
    pure newRecord
  where
    fqdn :: ByteString
    fqdn = mconcat [Text.encodeUtf8 leaf, ".",  dnsApex rt]

    newRecord :: DNS.ResourceRecord
    newRecord =
      DNS.ResourceRecord fqdn DNS.TXT DNS.classIN 300 $ DNS.RD_TXT $ Text.encodeUtf8 val

    insertRR xs = newRecord : List.filter otherFqdn xs

    otherFqdn :: DNS.ResourceRecord -> Bool
    otherFqdn (DNS.ResourceRecord qdn _ _ _ _) = fqdn /= qdn

handleDynamicRegistration :: Runtime -> Server Api
handleDynamicRegistration runtime =
  handleAutoRegister runtime
  :<|> handleTextRegister runtime
  :<|> handleListRegistrations runtime

handleAutoRegister :: Runtime -> DNSLeafName -> SockAddr -> Maybe Text -> Maybe ChallengeAttempt -> Handler AutoRegistrationResult
handleAutoRegister rt _ _ (Just _) _ = do
  liftIO $ do
    Prometheus.withLabel (cnt_registrations $ counters rt) "error" Prometheus.incCounter
    runTracer (tracer rt) $ RegistrationFailed ProxiedError
  throwError err400
handleAutoRegister rt _ _ _ Nothing = do
  liftIO $ do
    Prometheus.withLabel (cnt_registrations $ counters rt) "error" Prometheus.incCounter
    runTracer (tracer rt) $ RegistrationFailed AuthError
  throwError err403
handleAutoRegister rt dnsleaf sockaddr Nothing (Just hmac) = do
  let hashedpart = dnsleaf
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
        Just (ip,_) -> liftIO $ do
          rr <- addRRa success rt dnsleaf ip
          runTracer (tracer rt) $ RegistrationSuccess rr
          Prometheus.withLabel (cnt_registrations $ counters rt) "success" Prometheus.incCounter
          pure $ AutoRegistrationResult dnsleaf (Text.pack $ show ip)

handleTextRegister :: Runtime -> DNSLeafName -> Text -> Maybe ChallengeAttempt -> Handler (DNSLeafName, Text)
handleTextRegister rt dnsleaf textval Nothing = do
  liftIO $ do
    Prometheus.withLabel (cnt_registrations $ counters rt) "auth-error" Prometheus.incCounter
    runTracer (tracer rt) $ RegistrationFailed AuthError
  throwError err403
handleTextRegister rt dnsleaf textval (Just hmac) = do
  let hashedpart = dnsleaf
  let auth = verifyHmac rt hashedpart hmac
  case auth of
    Nothing -> do
      liftIO $ do
        Prometheus.withLabel (cnt_registrations $ counters rt) "auth-error" Prometheus.incCounter
        runTracer (tracer rt) $ RegistrationFailed AuthError
      throwError err403
    Just success -> liftIO $ do
      rr <- addText success rt dnsleaf textval
      runTracer (tracer rt) $ RegistrationSuccess rr
      pure (dnsleaf, textval)

handleListRegistrations :: Runtime -> Maybe ChallengeAttempt -> Handler Registrations
handleListRegistrations rt _ = do
  rrs <- liftIO $ readRRs rt
  pure $ Registrations $ map show rrs

type HashedPart = Text

data ActionAuthorized = ActionAuthorized

verifyHmac :: Runtime -> HashedPart -> ChallengeAttempt -> Maybe ActionAuthorized
verifyHmac rt hashedpart attempt =
  if attempt == expected
  then Just ActionAuthorized
  else Nothing
  where
    hmac = HMAC256.hmac (sharedHmacSecret rt) (Text.encodeUtf8 hashedpart)
    expected = Text.decodeUtf8 $ Base16.encode $ hmac
