module MicroDNS.DAI where

import Data.Text (Text)
import qualified Network.DNS as DNS
import Network.Socket (SockAddr, Socket)

type Reason = Text

data Response
    = Ignore Reason
    | RespondMessage !DNS.DNSMessage
    deriving (Show)

data Request
    = Request
    { requestAddr :: !SockAddr
    , requestMessage :: !DNS.DNSMessage
    }
    deriving (Show)

type Handler = Request -> (Response -> IO ()) -> IO ()

type Middleware = Handler -> Handler
