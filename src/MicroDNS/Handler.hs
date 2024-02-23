{-# LANGUAGE OverloadedStrings #-}
module MicroDNS.Handler where

import Control.Monad (forever, void)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Data.Coerce (coerce)
import Data.Streaming.Network (bindPortUDP)
import qualified Network.DNS as DNS
import Network.Socket (Socket, SockAddr)
import qualified Prometheus as Prometheus
import Prod.Tracer

import MicroDNS.Runtime
import MicroDNS.DAI

newtype Apex = Apex { getApex :: ByteString }
  deriving (Show, Eq, Ord)

endsWithDot :: ByteString -> Bool
endsWithDot bs =
  ByteString.takeEnd 1 bs == "."

apexify :: ByteString -> Apex
apexify bs
  | endsWithDot bs = Apex bs
  | otherwise = Apex (bs <> ".")

apexFromText :: Text -> Apex
apexFromText = apexify . Text.encodeUtf8

type QuestionLookup m = DNS.Question -> m [DNS.ResourceRecord]

ioLookup :: Applicative m => m [DNS.ResourceRecord] -> QuestionLookup m
ioLookup records q =
    lookupRecord <$> records <*> pure q

lookupRecord :: [DNS.ResourceRecord] -> DNS.Question -> [DNS.ResourceRecord]
lookupRecord records DNS.Question{DNS.qname = qname, DNS.qtype = qtype} =
    let
      exacts = filter matchExact records
      cnamed = filter matchCName records
      recursedOnce = filter (matchCNameRecursion cnamed) records
    in
    exacts <> cnamed <> recursedOnce
  where
    qname' = downcase qname

    matchExact (DNS.ResourceRecord name_ qtyp_ _ _ _) =
      qtyp_ == qtype && downcase name_ == qname'

    matchCName (DNS.ResourceRecord name_ qtyp_ _ _ _) =
      qtyp_ == DNS.CNAME && downcase name_ == qname'

    matchCNameRecursion :: [DNS.ResourceRecord] -> DNS.ResourceRecord -> Bool
    matchCNameRecursion cnames (DNS.ResourceRecord name_ qtyp_ _ _ _) =
      qtyp_ == qtype && any (matchCNameRecord (downcase name_)) cnames

    matchCNameRecord recordName (DNS.ResourceRecord _ _ _ _ (DNS.RD_CNAME cnamedName)) = downcase cnamedName == recordName
    matchCNameRecord _ _ = False

    downcase x = Text.toLower $ Text.decodeUtf8 x -- todo: better for dns

pureLookup :: Applicative m => [DNS.ResourceRecord] -> QuestionLookup m
pureLookup records = ioLookup (pure records)

handleQuestion :: Runtime -> QuestionLookup IO -> Handler
handleQuestion rt lookup (Request _ DNS.DNSMessage{ DNS.header = hdr, DNS.question = q }) = \respond -> do
    Prometheus.incCounter $ cnt_messages $ counters rt
    rrs <- traverse countingLookup q
    Prometheus.incCounter $ cnt_responses $ counters rt
    Prometheus.addCounter (cnt_rrs $ counters rt) (fromIntegral $ length rrs)
    respond $ respondRRs $ concat rrs
  where
    countingLookup :: QuestionLookup IO
    countingLookup q = do
      let fqdn = Text.decodeUtf8 $ DNS.qname q
      let qtype = Text.pack $ show $ DNS.qtype q
      Prometheus.withLabel (cnt_questions $ counters rt) (fqdn, qtype) Prometheus.incCounter
      lookup q
    respondRRs :: [DNS.ResourceRecord] -> Response
    respondRRs rrs = RespondMessage $ DNS.defaultResponse {
            DNS.header = (DNS.header DNS.defaultResponse) { DNS.identifier = DNS.identifier hdr },
            DNS.question = q,
            DNS.answer = rrs
    }
