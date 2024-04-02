{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

module Main where

import Control.Concurrent.Async
import Data.Coerce (coerce)
import Data.Maybe (catMaybes)
import qualified Network.DNS as DNS

import Options.Generic

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Text.IO as Text
import qualified Network.Wai.Handler.Warp as Warp
import qualified Network.Wai.Handler.WarpTLS as Warp
import qualified Network.Wai.Middleware.RequestLogger as RequestLogger
import qualified Paths_prodapi
import qualified Prod.App as Prod
import Prod.Status
import Prod.Tracer (tracePrint)
import qualified Text.Megaparsec as Megaparsec

import qualified MicroDNS
import qualified MicroDNS.DynamicRegistration as DynamicRegistration
import Servant

type DNSApex = Text

data Params
    = Plain
        { dnsPort :: Int <?> "DNS port number"
        , dnsApex :: Text <?> "delegated DNS apex"
        , webHmacSecretFile :: FilePath <?> "shared secret file for hmac"
        , webPort :: Int <?> "web console port number"
        , zoneFile :: FilePath <?> "zonefile"
        }
    | Tls
        { dnsPort :: Int <?> "DNS port number"
        , dnsApex :: Text <?> "delegated DNS apex"
        , webHmacSecretFile :: FilePath <?> "shared secret file for hmac"
        , webPort :: Int <?> "web console port number"
        , certFile :: FilePath <?> "certificate file"
        , keyFile :: FilePath <?> "key file"
        , zoneFile :: FilePath <?> "zonefile"
        }
    deriving (Generic, Show)
instance ParseRecord Params

main :: IO ()
main = do
    args <- getRecord "microdns"
    -- app glueing
    healthRt <- (Prod.alwaysReadyRuntime tracePrint)
    init <- Prod.initialize healthRt
    appRuntime <- initRuntime args
    let webapp =
            RequestLogger.logStdoutDev $
                Prod.app
                    init
                    apiStatus
                    (statusPage <> versionsSection [("prodapi", Paths_prodapi.version)])
                    (serveApi appRuntime)
                    (Proxy @Api)
    dnsrt <- MicroDNS.initRuntime (coerce $ dnsPort args) tracePrint
    configRRs <- loadConfigRRs (MicroDNS.apexFromText $ coerce $ dnsApex args) (coerce zoneFile args)
    _ <- traverse print configRRs
    let combinedRRs = DynamicRegistration.readRRs (dynamicRegistrationRuntime appRuntime) <> pure configRRs
    let dnsapp = MicroDNS.handleQuestion dnsrt (MicroDNS.ioLookup combinedRRs)

    let dns = MicroDNS.serve dnsrt dnsapp
    let web = runWebApp args webapp

    _ <-
        runConcurrently $
            (,,)
                <$> Concurrently web
                <*> Concurrently dns
    pure ()
  where
    runWebApp :: Params -> Application -> IO ()
    runWebApp params@(Plain _ _ _ _ _) webapp =
        let warpSettings = Warp.setPort (coerce $ webPort params) $ Warp.defaultSettings
         in Warp.runSettings warpSettings webapp
    runWebApp params@(Tls _ _ _ _ _ _ _) webapp =
        let tlsSettings = Warp.tlsSettings (coerce $ certFile params) (coerce $ keyFile params)
            warpTlsSettings = Warp.setPort (coerce $ webPort params) $ Warp.defaultSettings
         in Warp.runTLS tlsSettings warpTlsSettings webapp

    apiStatus :: IO Text
    apiStatus = pure "ok"

    loadConfigRRs :: MicroDNS.Apex -> FilePath -> IO [DNS.ResourceRecord]
    loadConfigRRs apex zfile = do
        zonecontent <- Megaparsec.parse MicroDNS.zoneFile zfile <$> Text.readFile zfile
        case zonecontent of
            Left err -> error $ show err
            Right zones -> pure $ MicroDNS.collectDirectives apex zones

type Api = DynamicRegistration.Api

data Runtime = Runtime
    { dynamicRegistrationRuntime :: DynamicRegistration.Runtime
    }

initRuntime :: Params -> IO Runtime
initRuntime params = do
    secret <- ByteString.readFile (coerce $ webHmacSecretFile params)
    Runtime
        <$> DynamicRegistration.initRuntime tracePrint secret (MicroDNS.apexFromText $ coerce $ dnsApex params)

serveApi :: Runtime -> Server Api
serveApi Runtime{..} = DynamicRegistration.handleDynamicRegistration dynamicRegistrationRuntime
