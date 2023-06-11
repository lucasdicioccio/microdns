{-# LANGUAGE OverloadedStrings #-}

module MicroDNS.Runtime where

import Control.Monad (forever, void)
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Data.Coerce (coerce)
import Data.Streaming.Network (bindPortUDP)
import qualified Network.DNS as DNS
import Network.Socket (Socket, SockAddr)
import Network.Socket.ByteString (recvFrom, sendTo)
import qualified Prometheus as Prometheus
import Prod.Tracer

import MicroDNS.DAI

data Trace
  = ParsingError DNS.DNSError
  | HandlingRequest Request
  | RequestHandled Request Response
  deriving (Show)

data Counters
  = Counters
      { cnt_packets   :: Prometheus.Counter
      , cnt_messages  :: Prometheus.Counter
      , cnt_questions :: Prometheus.Vector (Text,Text) Prometheus.Counter
      , cnt_responses  :: Prometheus.Counter
      , cnt_ignores    :: Prometheus.Counter
      , cnt_rrs  :: Prometheus.Counter
      }

initCounters :: IO Counters
initCounters =
  Counters
    <$>
      Prometheus.register
        (Prometheus.counter (Prometheus.Info "udp_packets" "number of UDP packets"))
    <*>
      Prometheus.register
        (Prometheus.counter (Prometheus.Info "dns_messages" "number of DNS messages"))
    <*>
      Prometheus.register
        (Prometheus.vector ("fqdn","type")
          (Prometheus.counter (Prometheus.Info "dns_questions" "number of DNS questions")))
    <*>
      Prometheus.register
        (Prometheus.counter (Prometheus.Info "dns_responses" "number of DNS responses"))
    <*>
      Prometheus.register
        (Prometheus.counter (Prometheus.Info "dns_ignores" "number of DNS requests ignored"))
    <*>
      Prometheus.register
        (Prometheus.counter (Prometheus.Info "dns_rrs" "number of DNS RRs"))

data Runtime = Runtime {
    dnsSocket :: Socket
  , tracer :: Tracer IO Trace
  , counters :: Counters
  }

initRuntime :: Int -> Tracer IO Trace -> IO Runtime
initRuntime portnum tracer =
  Runtime
    <$> bindPortUDP (coerce portnum) "*4"
    <*> pure tracer
    <*> initCounters
