{-# LANGUAGE DeriveDataTypeable    #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE RecordWildCards       #-}


module Main (main) where

import           Control.Applicative
import           Control.Monad
import           Control.Monad.Extra
import           Control.Monad.Trans.Class
import           Data.Binary                (decode, encode)
import           Data.Bits
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Char8      as BSC
import qualified Data.ByteString.Lazy       as LBS
import           Data.Char
import           Data.Maybe
import           Data.Monoid
import           Data.Time.Clock
import           Data.Time.LocalTime
import           Network.Security.Message
import           Network.Security.PFKey     (AddressPair (..), IPAddrPair (..))
import qualified Network.Security.PFKey     as PFKey
import           System.Console.CmdArgs
import           System.IO                  (stdin)
import           System.Socket              (AddressInfo (..), Stream, TCP,
                                             getAddressInfo)
import           System.Socket.Family.Inet  (Inet, SocketAddressInet (..))
import           System.Socket.Family.Inet6 (Inet6, SocketAddressInet6 (..))
import qualified Text.Parsec                as P
import qualified Text.Parsec.Prim           as P

data SetKey =
  SetKey
  { dump   :: Bool
  , flush  :: Bool
  , policy :: Bool
  , cmds   :: Bool
  } deriving (Show, Data, Typeable)

setkey =
  SetKey
  { dump = def &= name "D"  &= help
           "Dump the SAD entries.  If -P is also specified, the SPD entries are dumped.  If -p is specified, the ports are displayed."
  , flush = def &= name "F" &= help
            "Flush the SAD entries.  If -P is also specified, the SPD entries are flushed."
  , policy = def &= name "P" &= help "Policy entries"
  , cmds = def &= name "c" &= help "read commands from stdin"
  }
  &=
  verbosity &=
  help "" &=
  summary "hipsec v0.0.0.1, (C) Vladimir Sorokin 2011-2015 (https://github.com/vladsor/hipsec)" &=
  details ["",""
          ,"",""]

main :: IO ()
main = do
  opts <- cmdArgs setkey

  case policy opts of
    True -> do
      when (dump opts) $ do
        s <-PFKey.open
        doCommand s CommandSPDDump
        PFKey.close s
      when (flush opts) $ do
        putStrLn "SPD Flush"
        s <- PFKey.open
        doCommand s CommandSPDFlush
        PFKey.close s
    False -> do
      when (dump opts) $ do
        s <- PFKey.open
        doCommand s CommandDump
        PFKey.close s
      when (flush opts) $ do
        putStrLn "SAD Flush"
        s <- PFKey.open
        doCommand s CommandFlush
        PFKey.close s

  when (cmds opts) $ do
    raw <- getContents
    case (P.parse tokenize "" raw) of
      Left err -> print err
      Right xs -> do
        let xs' = filter (\i -> case i of
              TokenComment _ -> False
              _ -> True) xs
        r <- P.runParserT parser () "stdin" xs'
        case r of
          Left err' -> print err'
          Right cmds -> do
            print cmds
            s <- PFKey.open
            PFKey.sendRegister s SATypeUnspec
            PFKey.recvRegister s
            mapM_ (doCommand s) cmds
            PFKey.close s

doCommand :: PFKey.Socket -> Command -> IO ()
doCommand s CommandFlush = PFKey.sendFlush s SATypeUnspec
doCommand s CommandDump = do
        PFKey.sendDump s SATypeUnspec
        whileM $ do
          res <- PFKey.recv s
          case res of
            Nothing -> print "Nothing\n" >> return False
            Just msg -> do
              ct <- getCurrentTime
              tz <- getCurrentTimeZone
              putStrLn $ PFKey.dumpSA msg ct tz
              return $ (msgErrno msg == 0) && (msgSeq msg /= 0)
doCommand s CommandSPDFlush = PFKey.sendFlush s SATypeUnspec
doCommand s CommandSPDDump = do
        PFKey.sendSPDDump s
        whileM $ do
          res <- PFKey.recv s
          case res of
            Nothing -> print "Nothing\n" >> return False
            Just msg -> do
              tz <- getCurrentTimeZone
              PFKey.dumpSPD msg tz
              return $ (msgErrno msg == 0) && (msgSeq msg /= 0)
doCommand s (CommandAdd ap proto spi encAlg encKey authAlg authKey compAlg) =
  PFKey.sendAdd s proto IPSecModeAny ap spi 0 0 authAlg authKey encAlg encKey 0 Nothing Nothing 0
doCommand s (CommandGet ap proto spi) = do
        PFKey.sendGet s proto ap spi
        whileM $ do
          res <- PFKey.recv s
          case res of
            Nothing -> return False
            Just msg -> do
              ct <- getCurrentTime
              tz <- getCurrentTimeZone
              putStrLn $ PFKey.dumpSA msg ct tz
              return $ (msgErrno msg == 0) && (msgSeq msg /= 0)
doCommand s (CommandDelete ap proto spi) =
  PFKey.sendDelete s proto ap spi
doCommand s (CommandDeleteAll ap proto) =
  PFKey.sendDeleteAll s proto ap
doCommand s (CommandSPDAdd rng label policy) =
  PFKey.sendSPDAdd' s rng policy 0
doCommand s (CommandSPDAddTagged tag policy) = error "command 'spdadd tagged' not supported"
doCommand s (CommandSPDDelete rng policy) =
  PFKey.sendSPDDelete s rng policy 0
doCommand s (CommandSPDUpdate rng label policy) =
  PFKey.sendSPDUpdate s rng policy 0
doCommand s (CommandSPDUpdateTagged tag policy) = error "command 'spdupdate tagged' not supported"

data Token
  = Token { tknString :: String }
  | TokenNumber { tknNumber :: Int }
  | TokenHexString { tknHexString :: String }
  | TokenQuotedString { tknQuotedString :: String }
  | TokenEOC
  | TokenSlash
  | TokenSqBrOpen
  | TokenSqBrClose
  | TokenDot
  | TokenColon
  | TokenComment { tknComment :: String }
  deriving (Eq, Show)

separator = P.many1 (P.oneOf " \t\n")
tokenize = P.many $ do
  P.optionMaybe separator
  tkn <- P.choice
         [ P.char ';' >> return TokenEOC
         , P.char '#' >> P.many (P.noneOf "\n") >>= return . TokenComment
         , P.char '-' >> return (Token "-")
         , P.char '/' >> return TokenSlash
         , P.char '[' >> return TokenSqBrOpen
         , P.char ']' >> return TokenSqBrClose
         , P.char '.' >> return TokenDot
         , P.char ':' >> return TokenColon
         , P.between (P.char '"') (P.char '"') (liftM TokenQuotedString $ P.many (P.noneOf "\""))
         , P.char '0' >> ((P.oneOf "xX" >> (liftM TokenHexString $ P.many1 P.hexDigit)) <|>
                         (P.many1 P.digit >>= return . TokenNumber . (foldl (\a b -> a * 10 + digitToInt b) 0)))
         , P.many1 P.digit >>= return . TokenNumber . (foldl (\a b -> a * 10 + digitToInt b) 0)
         , P.many1 (P.noneOf " \t\n;#/[].:\"") >>= return . Token
         ]
  P.optionMaybe separator
  return tkn

satisfy :: P.Stream s m Token => (Token -> Bool) -> P.ParsecT s u m Token
satisfy f = P.tokenPrim (\c -> show c) (\pos _c _cs -> P.incSourceColumn pos 1)
                      (\c -> if f c then Just c else Nothing)

token :: P.Stream s m Token => String -> P.ParsecT s u m String
token str = (satisfy ( == (Token str))) >>= return . tknString

tokenString :: P.Stream s m Token => P.ParsecT s u m String
tokenString = (satisfy f) >>= return . tknString
  where
    f (Token _) = True
    f _ = False

tokenQuotedString :: P.Stream s m Token => P.ParsecT s u m String
tokenQuotedString = (satisfy f) >>= return . tknQuotedString
  where
    f (TokenQuotedString _) = True
    f _ = False

tokenHexString :: P.Stream s m Token => P.ParsecT s u m String
tokenHexString = (satisfy f) >>= return . tknHexString
  where
    f (TokenHexString _) = True
    f _ = False

tokenNumber :: P.Stream s m Token => P.ParsecT s u m Int
tokenNumber = liftM tknNumber (satisfy f) <|> liftM (foldl (\a b -> a * 16 + digitToInt b) 0) tokenHexString
  where
    f (TokenNumber _) = True
    f _ = False

tokenEOC :: P.Stream s m Token => P.ParsecT s u m ()
tokenEOC = (satisfy (== TokenEOC)) >> return ()

tokenSlash :: P.Stream s m Token => P.ParsecT s u m String
tokenSlash = (satisfy f) >>= return . tknString
  where
    f TokenSlash = True
    f _ = False

tokenSqBrOpen :: P.Stream s m Token => P.ParsecT s u m ()
tokenSqBrOpen = (satisfy f) >> return ()
  where
    f TokenSqBrOpen = True
    f _ = False

tokenSqBrClose :: P.Stream s m Token => P.ParsecT s u m ()
tokenSqBrClose = (satisfy f) >> return ()
  where
    f TokenSqBrClose = True
    f _ = False

tokenDot :: P.Stream s m Token => P.ParsecT s u m ()
tokenDot = (satisfy f) >> return ()
  where
    f TokenDot = True
    f _ = False

tokenKey :: P.Stream s m Token => P.ParsecT s u m Key
tokenKey = liftM Key $ (liftM BSC.pack tokenQuotedString) <|> (liftM (BS.pack . g) tokenHexString)
  where
    g ls = if length ls .&. 1 == 0 then go [] ls else go [] ("0" ++ ls)
    go acc (x1:x2:xs) = go (acc ++ [fromIntegral $ 16 * digitToInt x1 + digitToInt x2]) xs
    go acc _ = acc

type Parser r = forall s u. P.Stream s IO Token => P.ParsecT s u IO r

parser :: Parser [Command]
parser = P.many1 $ do
  cmd <- P.choice    [ cmdFlush
                     , cmdDump
                     , cmdSPDFlush
                     , cmdSPDDump
                     , cmdAdd
                     , cmdGet
                     , cmdDelete
                     , cmdDeleteAll
                     , cmdSPDAdd
                     , cmdSPDAddTagged
                     , cmdSPDUpdate
                     , cmdSPDUpdateTagged
                     , cmdSPDDelete
                     ]
  tokenEOC
  return cmd

cmdFlush :: Parser Command
cmdFlush = token "flush" >> return CommandFlush

cmdDump :: Parser Command
cmdDump = token "dump" >> return CommandDump

cmdSPDFlush :: Parser Command
cmdSPDFlush = token "spdflush" >> return CommandSPDFlush

cmdSPDDump :: Parser Command
cmdSPDDump = token "spddump" >> return CommandSPDDump

tokenIP4 :: Parser SocketAddressInet
tokenIP4 = do
  v1 <- liftM fromIntegral tokenNumber
  tokenDot
  v2 <- liftM fromIntegral tokenNumber
  tokenDot
  v3 <- liftM fromIntegral tokenNumber
  tokenDot
  v4 <- liftM fromIntegral tokenNumber
  ai <- liftM (socketAddress . head) $ lift (getAddressInfo (Just (BSC.pack (show v1 ++ "." ++ show v2 ++ "." ++ show v3 ++ "." ++ show v4))) Nothing mempty :: IO [AddressInfo Inet Stream TCP])
  return $ ai

tokenIPPair :: Parser IPAddrPair
tokenIPPair = do
  src <- tokenIP4
  dst <- tokenIP4
  return $ IPAddrPair4 src dst

cmdAdd :: Parser Command
cmdAdd = do
  token "add"
  addIPPair <- tokenIPPair
  addProto <- liftM read tokenString
  addSPI <- tokenNumber
  token "-"
  token "E"
  addEncAlg <- liftM read tokenString
  addEncKey <- tokenKey
  token "-"
  token "A"
  addAuthAlg <- liftM read tokenString
  addAuthKey <- tokenKey
  let addCompAlg = CompAlgNone

  return CommandAdd{..}

cmdGet :: Parser Command
cmdGet = do
  token "get"
  getIPPair <- tokenIPPair
  getProto <- liftM read tokenString
  getSPI <- tokenNumber
  return CommandGet{..}

cmdDelete :: Parser Command
cmdDelete = do
  token "delete"
  deleteIPPair <- tokenIPPair
  deleteProto <- liftM read tokenString
  deleteSPI <- tokenNumber
  return CommandDelete{..}

cmdDeleteAll :: Parser Command
cmdDeleteAll = do
  token "deleteall"
  deleteAllIPPair <- tokenIPPair
  deleteAllProto <- liftM read tokenString
  return CommandDeleteAll{..}

tokenSrcDst :: Parser (IPAddr, IPAddr)
tokenSrcDst = do
  SocketAddressInet src _ <- tokenIP4
  sport <- P.optionMaybe $ do
    tokenSqBrOpen
    port <- tokenNumber
    tokenSqBrClose
    return $ fromIntegral port
  token "-"
  SocketAddressInet dst _ <- tokenIP4
  dport <- P.optionMaybe $ do
    tokenSqBrOpen
    port <- tokenNumber
    tokenSqBrClose
    return $ fromIntegral port
  return (IPAddr4 $ SocketAddressInet src $ fromMaybe 0 sport, IPAddr4 $ SocketAddressInet dst $ fromMaybe 0 dport)

tokenPolicy :: Parser Policy
tokenPolicy = do
  policyDir <- liftM read tokenString
  policyType' <- P.optionMaybe $ liftM read tokenString
  case policyType' of
    Nothing -> do
      let policyType = IPSecPolicyNone
      let policyId = 0
      let policyPriority = 0
      let policyIPSecRequests = []
      return Policy{..}
    Just policyType -> do
      ipsecreqProto <- liftM read tokenString
      tokenSlash
      ipsecreqMode <- liftM read tokenString
      tokenSlash
      ipsecreqAddrs <- P.optionMaybe tokenSrcDst
      tokenSlash

      ipsecreqLevel <- liftM read tokenString

      let policyId = 0
      let policyPriority = 0
      let ipsecreqReqId = 0
      let policyIPSecRequests = return IPSecRequest{..}
      return Policy{..}


tokenAddressRange :: Parser (IPAddr, Int)
tokenAddressRange = do
  ip <- tokenIP4
  P.choice [ return (IPAddr4 ip, 32)
           , do
                tokenSlash
                pref <- tokenNumber
                return (IPAddr4 ip, pref)
           , do
                tokenSqBrOpen
                port <- tokenNumber
                tokenSqBrClose
                return (IPAddr4 ip, 32)
           , do
                tokenSlash
                pref <- tokenNumber
                tokenSqBrOpen
                port <- tokenNumber
                tokenSqBrClose
                return (IPAddr4 ip, pref)
           ]

tokenAddressPair :: Parser AddressPair
tokenAddressPair = do
  iapSrcAddr4 <- tokenIP4
  iapDstAddr4 <- tokenIP4
  let apIPAddrPair = IPAddrPair4{..}
  apProto <- liftM read tokenString
  let apSrcPrefixLen = 32
  let apDstPrefixLen = 32
  return AddressPair{..}

cmdSPDAdd :: Parser Command
cmdSPDAdd = do
  token "spdadd"
  spdAddRange <- tokenAddressPair
  token "-"
  token "P"
  let spdAddLabel = Nothing
  spdAddPolicy <- tokenPolicy
  return CommandSPDAdd{..}

cmdSPDAddTagged :: Parser Command
cmdSPDAddTagged = do
  token "spdadd"
  token "tagged"
  spdAddTaggedTag <- tokenQuotedString
  spdAddTaggedPolicy <- tokenPolicy
  return CommandSPDAddTagged{..}

cmdSPDUpdate :: Parser Command
cmdSPDUpdate = do
  token "spdupdate"
  spdUpdateRange <- tokenAddressPair
  token "-"
  token "P"
  let spdUpdateLabel = Nothing
  spdUpdatePolicy <- tokenPolicy
  return CommandSPDUpdate{..}

cmdSPDUpdateTagged :: Parser Command
cmdSPDUpdateTagged = do
  token "spdupdate"
  token "tagged"
  spdUpdateTaggedTag <- tokenQuotedString
  spdUpdateTaggedPolicy <- tokenPolicy
  return CommandSPDUpdateTagged{..}

cmdSPDDelete :: Parser Command
cmdSPDDelete = do
  token "spddelete"
  spdDeleteRange <- tokenAddressPair
  token "-"
  token "P"
  let spdAddLabel = Nothing
  spdDeletePolicy <- tokenPolicy
  return CommandSPDDelete{..}

data Command
  = CommandFlush
  | CommandDump
  | CommandSPDFlush
  | CommandSPDDump
  | CommandAdd
    { addIPPair  :: IPAddrPair
    , addProto   :: SAType
    , addSPI     :: Int
    , addEncAlg  :: EncAlg
    , addEncKey  :: Key
    , addAuthAlg :: AuthAlg
    , addAuthKey :: Key
    , addCompAlg :: CompAlg
    }
  | CommandGet
    { getIPPair :: IPAddrPair
    , getProto  :: SAType
    , getSPI    :: Int
    }
  | CommandDelete
    { deleteIPPair :: IPAddrPair
    , deleteProto  :: SAType
    , deleteSPI    :: Int
    }
  | CommandDeleteAll
    { deleteAllIPPair :: IPAddrPair
    , deleteAllProto  :: SAType
    }
  | CommandSPDAdd
    { spdAddRange  :: AddressPair
    , spdAddLabel  :: Maybe String
    , spdAddPolicy :: Policy
    }
  | CommandSPDAddTagged
    { spdAddTaggedTag    :: String
    , spdAddTaggedPolicy :: Policy
    }
  | CommandSPDUpdate
    { spdUpdateRange  :: AddressPair
    , spdUpdateLabel  :: Maybe String
    , spdUpdatePolicy :: Policy
    }
  | CommandSPDUpdateTagged
    { spdUpdateTaggedTag    :: String
    , spdUpdateTaggedPolicy :: Policy
    }
  | CommandSPDDelete
    { spdDeleteRange  :: AddressPair
    , spdDeletePolicy :: Policy
    }
  deriving (Eq, Show)
