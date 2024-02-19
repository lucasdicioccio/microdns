{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
module MicroDNS.MicroZone
  ( ZoneFile(..)
  , Directive(..)
  -- * parsing
  , zoneFile
  -- * exploitation
  , collectDirectives
  ) where

import Data.IP (IPv4, IPv6)
import Data.Word (Word16)
import Data.CaseInsensitive as CI
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.ByteString as ByteString
import qualified Network.DNS as DNS
import Text.Megaparsec
import Text.Megaparsec.Char (alphaNumChar, digitChar, hexDigitChar, string, space, newline)
import Data.Void (Void)

import MicroDNS.Handler (Apex(..), apexify, apexFromText, endsWithDot)

data ZoneFile
  = ZoneFile
  { directives :: [ Directive ]
  }
  deriving (Show)

type CommentedText = Text

data GuardedCommand
  = SetApex Text
  deriving (Show)

data Directive
  = Comment CommentedText
  | Command GuardedCommand
  | Record DNS.ResourceRecord
  deriving (Show)

type Parser = Parsec Void Text

zoneFile :: Parser ZoneFile
zoneFile =
  ZoneFile <$> (directive `sepEndBy` skipSome newline) <* eof

directive :: Parser Directive
directive = choice
  [ (Comment <$> comment)
  , (Command <$> command)
  , (Record <$> record)
  ]

comment :: Parser CommentedText
comment = string "--" *> space *> takeWhile1P Nothing ((/=) '\n')

command :: Parser GuardedCommand
command =
    choice
    [ SetApex <$> apex
    ]
  where
    apex = string "microdns:apex" *> space *> domainName

record :: Parser DNS.ResourceRecord
record =
    choice
    [ txtRecord
    -- aaaa first to avoid a valid 'a' prefix parse
    , aaaaRecord
    , aRecord
    , caaRecord
    , cnameRecord
    , mxRecord
    , srvRecord
    ]

txtRecord :: Parser DNS.ResourceRecord
txtRecord = do
  _ <- string "TXT"
  _ <- space
  !domain <- Text.encodeUtf8 <$> apexOrDomainName
  _ <- space
  !val <- Text.encodeUtf8 <$> quotedString
  pure $ DNS.ResourceRecord domain DNS.TXT DNS.classIN 300 $ DNS.RD_TXT val

aRecord :: Parser DNS.ResourceRecord
aRecord = do
  _ <- string "A"
  _ <- space
  !domain <- Text.encodeUtf8 <$> apexOrDomainName
  _ <- space
  !val <- ipv4
  pure $ DNS.ResourceRecord domain DNS.A DNS.classIN 300 $ DNS.RD_A val

aaaaRecord :: Parser DNS.ResourceRecord
aaaaRecord = do
  _ <- string "AAAA"
  _ <- space
  !domain <- Text.encodeUtf8 <$> apexOrDomainName
  _ <- space
  !val <- ipv6
  pure $ DNS.ResourceRecord domain DNS.AAAA DNS.classIN 300 $ DNS.RD_AAAA val

caaRecord :: Parser DNS.ResourceRecord
caaRecord = do
  _ <- string "CAA"
  _ <- space
  !domain <- Text.encodeUtf8 <$> apexOrDomainName
  _ <- space
  !key <- CI.mk . Text.encodeUtf8 <$> quotedString
  _ <- space
  !val <- Text.encodeUtf8 <$> quotedString
  pure $ DNS.ResourceRecord domain DNS.CAA DNS.classIN 300 $ DNS.RD_CAA 0 key val

cnameRecord :: Parser DNS.ResourceRecord
cnameRecord = do
  _ <- string "CNAME"
  _ <- space
  !domain <- Text.encodeUtf8 <$> apexOrDomainName
  _ <- space
  !val <- Text.encodeUtf8 <$> domainName
  pure $ DNS.ResourceRecord domain DNS.CNAME DNS.classIN 300 $ DNS.RD_CNAME val

mxRecord :: Parser DNS.ResourceRecord
mxRecord = do
  _ <- string "MX"
  _ <- space
  !domain <- Text.encodeUtf8 <$> apexOrDomainName
  _ <- space
  !priority <- mxPriority
  _ <- space
  !val <- Text.encodeUtf8 <$> domainName
  pure $ DNS.ResourceRecord domain DNS.MX DNS.classIN 300 $ DNS.RD_MX priority val

srvRecord :: Parser DNS.ResourceRecord
srvRecord = do
  _ <- string "SRV"
  _ <- space
  !domain <- Text.encodeUtf8 <$> apexOrDomainName
  _ <- space
  !priority <- srvPriority
  _ <- space
  !port <- srvPortnum
  _ <- space
  !val <- Text.encodeUtf8 <$> domainName
  pure $ DNS.ResourceRecord domain DNS.SRV DNS.classIN 300 $ DNS.RD_SRV priority 1 port val

apexOrDomainName :: Parser Text
apexOrDomainName =
  (string "@" *> pure "") <|> domainName

domainName :: Parser Text
domainName =
  Text.pack
    <$> many (alphaNumChar <|> oneOf ['.','-','_'])

quotedString :: Parser Text
quotedString =
    Text.pack
      <$> between (string "\"") (string "\"") contents
  where
    contents :: Parser [Char]
    contents = many (escapedChar <|> plainChar)

    escapedChar :: Parser Char
    escapedChar = backspace <|> quote

    backspace :: Parser Char
    backspace = string "\\\\" *> pure '\\'

    quote :: Parser Char
    quote = string "\\\"" *> pure '"'

    plainChar :: Parser Char
    plainChar = noneOf ['\\', '"']

ipv4 :: Parser IPv4
ipv4 = read <$> many (digitChar <|> oneOf ['.'])

ipv6 :: Parser IPv6
ipv6 = read <$> many (hexDigitChar <|> oneOf [':','.'])

mxPriority,srvPriority,srvPortnum :: Parser Word16
mxPriority = read <$> many (digitChar)
srvPriority = read <$> many (digitChar)
srvPortnum = read <$> many (digitChar)

collectDirectives :: Apex -> ZoneFile -> [DNS.ResourceRecord]
collectDirectives defaultApex zones =
    go defaultApex [] (directives zones)
  where
    go :: Apex -> [DNS.ResourceRecord] -> [Directive] -> [DNS.ResourceRecord]
    go _ xs [] = xs
    go a xs ((Comment _):ds) = go a xs ds 
    go _ xs ((Command (SetApex a)):ds) = go (apexFromText a) xs ds
    go a xs ((Record rec):ds) = go a (adapt a rec:xs) ds

    adapt :: Apex -> DNS.ResourceRecord -> DNS.ResourceRecord
    adapt apex rr
      | matchSuffix apex rr = rr
      | otherwise = rr { DNS.rrname = addApex apex (DNS.rrname rr) }

    addApex :: Apex -> ByteString.ByteString -> ByteString.ByteString
    addApex apex "" = getApex apex
    addApex apex bs = if endsWithDot bs then mconcat [bs, getApex apex] else mconcat [bs, ".", getApex apex]

    matchSuffix :: Apex -> DNS.ResourceRecord -> Bool
    matchSuffix apex rr = getApex apex `ByteString.isSuffixOf` getApex (apexify $ DNS.rrname rr)
