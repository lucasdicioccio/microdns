module MicroDNS.Server where

import Control.Monad (forever, void)
import Data.ByteString (ByteString)
import qualified Network.DNS as DNS
import Network.Socket (SockAddr, Socket)
import Network.Socket.ByteString (recvFrom, sendTo)
import Prod.Tracer (runTracer)
import qualified Prometheus as Prometheus

import MicroDNS.DAI
import MicroDNS.Runtime

serve :: Runtime -> Handler -> IO ()
serve rt@Runtime{dnsSocket = skt} handler = do
    forever $ do
        (bs, addr) <- recvFrom skt (fromIntegral DNS.maxUdpSize)
        Prometheus.incCounter $ cnt_packets $ counters rt
        case parseDNS bs of
            Left err -> parsingError err
            Right q -> do
                let req = Request addr q
                runTracer (tracer rt) $ HandlingRequest req
                handler req (reply req)
  where
    reply :: Request -> Response -> IO ()
    reply req rsp = do
        runTracer (tracer rt) $ RequestHandled req rsp
        case rsp of
            (RespondMessage resp) -> void $ sendTo skt (DNS.encode resp) (requestAddr req)
            Ignore _ -> pure ()

    parsingError :: DNS.DNSError -> IO ()
    parsingError = runTracer (tracer rt) . ParsingError

    parseDNS :: ByteString -> Either DNS.DNSError DNS.DNSMessage
    parseDNS bs = do
        q <- DNS.decode bs
        if DNS.qOrR (DNS.flags (DNS.header q)) == DNS.QR_Query
            then return q
            else Left DNS.FormatError
