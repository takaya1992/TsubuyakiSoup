//======================================================================
//    TsubuyakiSoup
//----------------------------------------------------------------------
//    HSPからTwitterを操作するモジュール。
//    OAuth/xAuthに対応しているため、BASIC認証が廃止された今日でも
//  TwitterAPIを利用することができます。
//----------------------------------------------------------------------
//  Version : 1.6
//  Author : Takaya
//  CreateDate : 10/07/29
//  LastUpdate : 11/09/14
//======================================================================
/*  [HDL module infomation]

%dll
TsubuyakiSoup

%ver
1.1

%date
2010/11/14

%note
TsubuyakiSoup.asをインクルードすること。

%port
Win

%*/

#include "encode.as"
#undef                  sjis2utf8n(%1, %2)
#define global          sjis2utf8n(%1, %2) _FromSJIS@mod_encode %2, CODEPAGE_S_JIS, %1, CODEPAGE_UTF_8
#undef                  utf8n2sjis(%1)
#define global ctype    utf8n2sjis(%1)     _ToSJIS@mod_encode(%1, CODEPAGE_UTF_8,  CODEPAGE_S_JIS)



//  ------------------------------------------------------------
//    モジュール開始
#module TsubuyakiSoup

//------------------------------
//  WinAPI
//------------------------------
//---------------
//  advapi32.dll
//---------------
#uselib "advapi32.dll"
#cfunc _CryptAcquireContext "CryptAcquireContextA" var, sptr, sptr, int, int
#cfunc _CryptCreateHash "CryptCreateHash" sptr, int, int, int, var
#cfunc _CryptHashData "CryptHashData" sptr, sptr, int, int
#cfunc _CryptSetHashParam "CryptSetHashParam" sptr, int, var, int
#cfunc _CryptGetHashParam "CryptGetHashParam" sptr, int, sptr, var, int
#cfunc _CryptImportKey "CryptImportKey" sptr, var, int, int, int, var
#func _CryptDestroyKey "CryptDestroyKey" int
#func _CryptDestroyHash "CryptDestroyHash" int
#func _CryptReleaseContext "CryptReleaseContext" int, int
#cfunc _CryptDeriveKey "CryptDeriveKey" int, int, int, int, var
#cfunc _CryptEncrypt "CryptEncrypt" int, int, int, int, int, var, int
#cfunc _CryptDecrypt "CryptDecrypt" int, int, int, int, var, var
//---------------
//  wininet.dll
//---------------
#uselib "wininet.dll"
#cfunc _InternetOpen "InternetOpenA" sptr, int, sptr, sptr, int
#cfunc _InternetOpenUrl "InternetOpenUrlA" int, str, sptr, int, int, int
#func _InternetReadFile "InternetReadFile" int, var, int, var
#func _InternetCloseHandle "InternetCloseHandle" int
#cfunc _InternetConnect "InternetConnectA" int, str, int, sptr, sptr, int, int, int
#cfunc _HttpOpenRequest "HttpOpenRequestA" int, sptr, str, sptr, sptr, sptr, int, int
#cfunc _HttpSendRequest "HttpSendRequestA" int, sptr, int, sptr, int
#cfunc _HttpQueryInfo "HttpQueryInfoA" int, int, var, var, int
#func _InternetQueryDataAvailable "InternetQueryDataAvailable" int, var, int, int
#func _InternetSetOption "InternetSetOptionA" int, int, int, int
//---------------
//  crtdll.dll
//---------------
#uselib "crtdll.dll"
#func _time "time" var




//------------------------------
//  定数
//------------------------------
//HTTPメソッド
#define global METHOD_GET	0
#define global METHOD_POST	1
#define global FORMAT_JSON	0
#define global FORMAT_XML	1




//============================================================
/*  [HDL symbol infomation]

%index
Encryption
文字列を暗号化してファイルに保存

%prm
(p1, p2)
p1 = 変数      : 暗号化する文字列を代入した変数
p2 = 文字列    : 鍵とする文字列
p3 = 文字列    : ファイル名

%inst
文字列をRC4アルゴリズムで暗号化しファイルに保存します。成功すると 1 、失敗すると 0 が返ります。

暗号化する文字列を代入した変数をp1に指定します。暗号化された文字列はp1の変数に返ります。

暗号化するための鍵（キー）は、p2に文字列として指定します。

関数実行時に、p1の変数の内容が書き換えられてしまうことに気をつけてください。

この関数で暗号化されたファイルは、Decryption関数で平文に復号することができます。

%group
TsubuyakiSoup補助関数

%href
Decryption

%*/
//------------------------------------------------------------
#defcfunc Encryption var p1, str p2, str p3
	EncryptStrLen = strlen(p1)
	EncryptStrLen2 = strlen(p1)
	refstat = 0
	if ( _CryptAcquireContext(hProv, 0, 0, 1, 0) = 0) {
		 if ( _CryptAcquireContext(hProv, 0, "Microsoft Enhanced Cryptographic Provider v1.0", 1, 0x00000008) = 0) {
		 	return 0
		 }
	}
	//ハッシュ作成
	if ( _CryptCreateHash(hProv, 0x00008004, 0, 0, hHash) ) {
		//ハッシュ値計算
		if ( _CryptHashData(hHash, p2, strlen(p2)+1, 0) ) {
			//暗号鍵の生成
			if ( _CryptDeriveKey(hProv, 0x00006801, hHash, 0x800000, hKey) ) {
				//暗号化
				if ( _CryptEncrypt( hKey, 0, 1, 0, 0, EncryptStrLen, 0) ) {		;バッファの確保用
					memexpand p1, EncryptStrLen
					if ( _CryptEncrypt( hKey, 0, 1, 0, varptr(p1), EncryptStrLen2, EncryptStrLen) ) {	;暗号化
						refstat = 1
					}
				}
				_CryptDestroyKey hKey
			}
		}
		_CryptDestroyHash hHash
	}
	_CryptReleaseContext hProv, 0
	bsave p3, p1
return refstat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
Decryption
暗号化されたファイルを復号

%prm
(p1, p2)
p1 = 変数      : 復号した文字列を代入する変数
p2 = 文字列    : 鍵とする文字列
p3 = 文字列    : ファイル名

%inst
RC4アルゴリズムで暗号化されたファイルを復号します。成功すると 1 、失敗すると 0 が返ります。

復号した文字列を代入する変数をp1に指定します。

復号するための鍵（キー）は、p2に文字列として指定します。

p3には、暗号化されたファイルの名前を指定します。ファイルの存在チェックなどはしていないので、スクリプト側でチェックしてください。

%group
TsubuyakiSoup補助関数

%href
Encryption

%*/
//------------------------------------------------------------
#defcfunc Decryption var p1, str p2, str p3
	exist p3
	sdim p1, strsize
	bload p3, p1
	EncryptStrLen = strsize
	refstat = 0
	if ( _CryptAcquireContext(hProv, 0, 0, 1, 0) = 0) {
		 if ( _CryptAcquireContext(hProv, 0, "Microsoft Enhanced Cryptographic Provider v1.0", 1, 0x00000008) = 0) {
		 	return 0
		}
	}
	//ハッシュ作成
	if ( _CryptCreateHash(hProv, 0x00008004, 0, 0, hHash) ) {
		//ハッシュ値計算
		if ( _CryptHashData(hHash, p2, strlen(p2), 0) ) {
			//暗号鍵の生成
			if ( _CryptDeriveKey(hProv, 0x00006801, hHash, 0x800000, hKey) ) {
				//復号
				if ( _CryptDecrypt( hKey, 0, 1, 0, p1, EncryptStrLen) ) {
					refstat = 1
				}
				_CryptDestroyKey hKey
			}
		}
		_CryptDestroyHash hHash
	}
	_CryptReleaseContext hProv, 0
return refstat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
HMAC_SHA1
HMAC-SHA1で署名を生成

%prm
(p1, p2)
p1 = 文字列    : 署名化する文字列
p2 = 文字列    : 鍵とする文字列

%inst
SHA-1ハッシュ関数を使用したハッシュメッセージ認証コード（HMAC）を返します。

p1に署名化する文字列を指定します。

署名化するための鍵（キー）は、p2で文字列で指定します。

%href
SignatureEncode

%group
TsubuyakiSoup補助関数

%*/
//------------------------------------------------------------
#defcfunc HMAC_SHA1 str p1, str p2
	HS_p1 = p1
	HS_p2 = p2
	HS_SigLen = 0
	HS_dest = ""
	//ハッシュ
	HS_hProv = 0
	HS_hKey = 0
	HS_hHash = 0
	sdim HS_HmacInfo,14
	lpoke HS_HmacInfo, 0, 0x00008004
	;keyの生成
	dim HS_keyBlob,350
	poke HS_keyBlob,0,0x8					;bType
	poke HS_keyBlob,1,2						;bVersion
	lpoke HS_keyBlob,2,0					;reserved
	HS_keyBlob(1) = 0x00006602				;aiKeyAlg
	HS_keyBlob(2) = strlen(HS_p2)	;len
	memcpy HS_keyBlob, HS_p2, HS_keyBlob(2), 12, 0
	//コンテキストの取得
	if ( _CryptAcquireContext(HS_hProv, 0, 0, 1, 0) ) {
		//キーのインポート
		if ( _CryptImportKey(HS_hProv, HS_keyBlob, (12+HS_keyBlob(2)), 0, 0x00000100, HS_hKey) ) {
			//ハッシュ初期化
			if ( _CryptCreateHash(HS_hProv, 0x00008009, HS_hKey, 0, HS_hHash) ) {
				//ハッシュパラメータの設定
				if ( _CryptSetHashParam(HS_hHash, 0x0005, HS_HmacInfo, 0) ) {
					//ハッシュに書き込み
					if ( _CryptHashData(HS_hHash, HS_p1, strlen(HS_p1), 0) ) {
						//ハッシュ取得
						if ( _CryptGetHashParam(HS_hHash, 0x0002, 0, HS_size, 0) ) {
							sdim HS_dest, HS_size
							if ( _CryptGetHashParam(HS_hHash, 0x0002, varptr(HS_dest), HS_size, 0) ) {
							}
						}
					}
				}
				//ハッシュハンドルの破棄
				_CryptDestroyHash HS_hHash
			}
			//キーハンドルの破棄
			_CryptDestroyKey HS_hKey
		}
		//ハンドルの破棄
		_CryptReleaseContext HS_hProv, 0
	}
return HS_dest
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
SignatureEncode
OAuth/xAuth用シグネチャを生成

%prm
(p1, p2)
p1 = 文字列    : 署名化する文字列
p2 = 文字列    : 鍵とする文字列

%inst
OAuth/xAuth用の署名を返します。

p1に署名化する文字列を指定します。

署名化するための鍵（キー）は、p2で文字列で指定します。

Twitterのシグネチャ生成の仕様より、
文字コードUTF-8でURLエンコードした文字列（p1）を、同じくURLエンコードした文字列（p2）をキーとしてHAMAC-SHA1方式で生成した署名を、BASE64エンコードしたうえURLエンコードしています。

%href
HMAC_SHA1

%group
TsubuyakiSoup補助関数

%*/
//------------------------------------------------------------
#defcfunc SignatureEncode str p1, str p2
	//utf-8へ変換
	sjis2utf8n SigTmp, p1
	sjis2utf8n SecretTmp, p2
	//URLエンコード。
	SigEnc = form_encode( SigTmp, 0)
	SecretEnc = form_encode( SecretTmp, 0)
	//HMAC-SHA1
	SigTmp = HMAC_SHA1( SigEnc, SecretEnc)
	//BASE64
	SigEnc = base64encode(SigTmp)
	//URLエンコード
	SigTmp = form_encode( SigEnc, 0)
return SigTmp
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
RESTAPI
TwitterAPIを実行

%prm
p1, p2, p3, p4, p5
p1 = 変数      : 応答結果を代入する変数
p2 = 変数      : レスポンスヘッダを代入する変数
p3 = 0～1(0)   : メソッド GET(0) POST(1)
p4 = 文字列    : API
p5 = 配列      : APIに添加する引数を代入した文字列配列

%inst
TwitterAPIを実行し、Twitterから返ってきたステータスコードを戻り値としてstatに返します。

p1,p2にはそれぞれ応答結果とヘッダを代入する文字列型変数を指定します。

p3でメソッドを指定することができます。"GET"で送信する場合は 0 を、"POST"で送信する場合は 1 を指定してください。その他の値を指定した場合は、自動的に"GET"メソッドを使用します。
TwitterAPIで指定されているメソッドを選択してください。

p4で実行するTwitterAPIを取得したいフォーマットとともに指定します。
    例 : "statuses/mentions.xml"      自分への言及をXML形式で取得
         "statuses/update.json"       Twitterへ投稿し、結果をJSON形式で取得
なお、TwitterAPIごとに指定できるフォーマットが決まっているので気をつけてください。


TwitterAPIに渡す引数を文字列型の配列にしてp5に指定します。
例えば、API"home_timeline"に引数"trim_user=true"と"count=50"を指定して、ホームタイムラインをユーザ情報をユーザIDだけにして50件取得するとします。
    Argument(0) = "trim_user=true"
    Argument(1) = "count=50"
    RESTAPI ResponseBody, ResponseHeader, 0, "statuses/home_timeline.xml", Argument


シグネチャの付加などは命令側でしていますので、TwitterAPIのリファレンスに記載されている引数以外は指定する必要はありません。
また、"oauth/request_token"と"oauth/access_token"を呼び出す際、引数の
"oauth_consumer_key","oauth_nonce","oauth_signature_method","oauth_timestamp","oauth_token","oauth_version","oauth_signature"については命令側で処理・付加していますので、指定しないでください。
例として、認証方式にxAuthを使い"oauth/access_token"でアクセストークンを取得する処理
    Argument(0) = "x_auth_mode=client_auth"
    Argument(1) = "x_auth_password=xxxxxx"
    Argument(2) = "x_auth_username=xxxxxxxx"
    RESTAPI ResponseBody, ResponseHeader, 1, "oauth/access_token", Argument
^

%group
TwitterAPI操作命令

%url
http://watcher.moe-nifty.com/memo/docs/twitterAPI.txt

%*/
//------------------------------------------------------------
#deffunc RESTAPI var p1, var p2, int p3, str p4, array p5
//  引数チェック＆初期化
	sdim p1
	sdim p2
	API = p4
	if vartype(p5) != 2 : return 0
	hConnect = 0		//InternetConnectのハンドル
	hRequest = 0		//HttpOpenRequestのハンドル
	API_statcode = 0	//リクエストの結果コード
	API_p1Length = 0	//データ長
	API_rsize = 1024	//バッファ初期値
	API_hsize = 0		//取得したバイト数が代入される変数
//  メソッドの設定
	if (p3 = 1) {
		Method = "POST"
	} else {
		Method = "GET"
	}
//  ポート＆フラグの設定
	UsePort = 443 : RequestFlag = -2139082752
	VersionStr = "1/"
	TokenStr = TS_AccessToken
	SigKey = TS_Consumer_Secret+" "+TS_AccessTokenSecret
	if (strmid(API,0,5) = "oauth") {
		VersionStr = ""
		if (API = "oauth/access_token") {
			//OAuth認証だったら、
			repeat length(p5)
				if (p5(cnt) = "x_auth_mode=client_auth") : break
				if cnt = length(p5)-1 : TokenStr = TS_RequestToken : SigKey = TS_Consumer_Secret+" "+TS_RequestTokenSecret
			loop
		}
	}
//  シグネチャ生成
	SigArrayMax = 6 + length(p5)
	sdim SigArray, 500, SigArrayMax
	SigNonce = RandomString(8,32)
	_time SigTime
	SigArray(0) = "oauth_consumer_key=" + TS_Consumer_Key
	SigArray(1) = "oauth_nonce=" + SigNonce
	SigArray(2) = "oauth_signature_method=HMAC-SHA1"
	SigArray(3) = "oauth_timestamp=" + SigTime
	SigArray(4) = "oauth_token="+ TokenStr
	SigArray(5) = "oauth_version=1.0"
	repeat SigArrayMax - 6
		SigArray(6+cnt) = p5(cnt)
	loop
	//ソート
	SortString SigArray
	//"&"で連結
	TransStr = ""+ Method +" https://api.twitter.com/"+ VersionStr + API +" "
	repeat SigArrayMax
		if SigArray(cnt) = "" : continue
		TransStr += SigArray(cnt) +"&"
	loop
	TransStr = strmid(TransStr, 0, strlen(TransStr)-1)
	Signature = SignatureEncode(TransStr, SigKey)
//  データ整形
	if (p3 = 1) {
		//POST
		PostStr = ""
		repeat SigArrayMax
			PostStr += SigArray(cnt) +"&"
		loop
		PostStr += "oauth_signature="+ Signature
		PostStrLen = strlen(PostStr)
		AddUrl = ""
	} else {
		//GET
		PostStr = 0
		PostStrLen = 0
		AddUrl = "?"
		repeat SigArrayMax
			AddUrl += SigArray(cnt) +"&"
		loop
		AddUrl += "oauth_signature="+ Signature
	}
	//サーバへ接続
	hConnect = _InternetConnect(TS_hInet, "api.twitter.com", UsePort, 0, 0, 3, 0, 0)
	if (hConnect) {
		//リクエストの初期化
		hRequest = _HttpOpenRequest(hConnect, Method, VersionStr+API+AddUrl, "HTTP/1.1", 0, 0, RequestFlag, 0)
		if (hRequest) {
			//サーバへリクエスト送信
			if ( _HttpSendRequest(hRequest, "Accept-Encoding: gzip, deflate", -1, PostStr, PostStrLen)) {
				//ヘッダを取得する変数の初期化
				p2Size = 3000
				sdim p2, p2Size
				//ヘッダの取得
				if ( _HttpQueryInfo(hRequest, 22, p2, p2Size, 0) ) {
					//ヘッダの解析
					notesel p2
					repeat notemax
						noteget API_BufStr, cnt
						API_buf = instr(API_BufStr, 0, "Status: ")				//ステータスコード
						if (API_Buf != -1) : API_statcode = int(strmid(API_BufStr, API_buf+8, 3))
						API_buf = instr(API_BufStr, 0, "Content-Length: ")		//長さ
						if (API_Buf != -1) : API_p1Length = int(strmid(API_BufStr, -1, strlen(API_BufStr)-API_buf+16))
						API_buf = instr(API_BufStr, 0, "X-RateLimit-Limit: ")		//60分間にAPIを実行できる回数
						if (API_Buf != -1) : TS_RateLimit(0) = int(strmid(API_BufStr, -1, strlen(API_BufStr)-(API_buf+19)))
						API_buf = instr(API_BufStr, 0, "X-RateLimit-Remaining: ")	//APIを実行できる残り回数
						if (API_Buf != -1) : TS_RateLimit(1) = int(strmid(API_BufStr, -1, strlen(API_BufStr)-(API_buf+23)))
						API_buf = instr(API_BufStr, 0, "X-RateLimit-Reset: ")		//リセットする時間
						if (API_Buf != -1) : TS_RateLimit(2) = int(strmid(API_BufStr, -1, strlen(API_BufStr)-(API_buf+19)))
					loop
					noteunsel
					//入手可能なデータ量を取得
					_InternetQueryDataAvailable hRequest, API_rsize, 0, 0
					//バッファの初期化
					sdim API_bufStr, API_rsize+1
					sdim p1, API_p1Length+1
					repeat 
						_InternetReadFile hRequest, API_bufStr, API_rsize, API_hsize
						if (API_hsize = 0) : break 
						p1 += strmid(API_bufStr, 0, API_hsize)
						await 0
					loop
				} else {
					//ヘッダの取得ができなかった場合
					API_statcode = -1
				}
			} else {
				//サーバへリクエスト送信できなかった場合
				API_statcode = -2
			}
			//Requestハンドルの破棄
			_InternetCloseHandle hRequest
		} else {
			//Requestハンドルを取得できなかった場合
			API_statcode = -3
		}
		//Connectハンドルの破棄
		_InternetCloseHandle hConnect
	} else {
		//Connectハンドルを取得できなかった場合
		API_statcode = -4
	}
return API_statcode
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
SearchAPI
ステータスを検索

%prm
p1, p2, p3, p4, p5
p1 = 変数      : 応答結果を代入する変数
p2 = 変数      : レスポンスヘッダを代入する変数
p3 = 文字列    : API
p5 = 配列      : APIに添加する引数を代入した文字列配列

%inst
SearchAPIを実行し、Twitterから返ってきたステータスコードを戻り値としてstatに返します。

p1,p2にはそれぞれ応答結果とヘッダを代入する文字列型変数を指定します。

p3で実行するSearchAPIを取得したいフォーマットとともに指定します。
    例 : "search.atom"      検索結果をATOM形式で取得
         "trends.json"      いま、Twitter でホットな話題をJSON形式で取得
なお、SearchAPIごとに指定できるフォーマットが決まっているので気をつけてください。

TwitterAPIに渡す引数を文字列型の配列にしてp4に指定します。
例えば、API"search"に引数"q=hsp"と"rpp=50"を指定して、"hsp"が含まれたステータスを検索し、50件取得するとします。
    Argument(0) = "q=hsp"
    Argument(1) = "rpp=50"
    SearchAPI ResponseBody, ResponseHeader, "search.atom", Argument

TS_Initでユーザエージェントを指定していない場合、厳しいAPI制限を受けることがあります。

%href
TS_Init

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc SearchAPI var p1, var p2, str p3, array p4
	sdim p1
	sdim p2
	if vartype(p4) != 2 : return 0
	hConnect = 0		//InternetConnectのハンドル
	hRequest = 0		//HttpOpenRequestのハンドル
	API_statcode = 0	//リクエストの結果コード
	API_p1Length = 0	//データ長
	API_rsize = 1024	//バッファ初期値
	API_hsize = 0		//取得したバイト数が代入される変数
	// 
	AddUrl = ""
	repeat length(p4)
		if length(p4) = cnt + 1 : AddUrl += p4(cnt) : break
		AddUrl += ""+ p4(cnt) +"&"
	loop
	hConnect = _InternetConnect(TS_hInet, "search.twitter.com", 80, 0, 0, 3, 0, 0)
	if (hConnect) {
		//リクエストの初期化
		hRequest = _HttpOpenRequest(hConnect, "GET", p3 +"?"+ AddUrl, "HTTP/1.1", 0, 0, -2147483648, 0)
		if (hRequest) {
			//サーバへリクエスト送信
			if ( _HttpSendRequest(hRequest, 0, 0, 0, 0)) {
				//ヘッダを取得する変数の初期化
				p2Size = 3000
				sdim p2, p2Size
				//ヘッダの取得
				if ( _HttpQueryInfo(hRequest, 22, p2, p2Size, 0) ) {
					notesel p2
					repeat notemax
						noteget API_BufStr, cnt
						API_buf = instr(API_BufStr, 0, "Status: ")				//ステータスコード
						if (API_Buf != -1) : API_statcode = int(strmid(API_BufStr, API_buf+8, 3))
						API_buf = instr(API_BufStr, 0, "Content-Length: ")		//長さ
						if (API_Buf != -1) : API_p1Length = int(strmid(API_BufStr, -1, strlen(API_BufStr)-API_buf+16))
					loop
					noteunsel
					//入手可能なデータ量を取得
					_InternetQueryDataAvailable hRequest, API_rsize, 0, 0
					//バッファの初期化
					sdim API_bufStr, API_rsize+1
					sdim p1, API_p1Length+1
					repeat 
						_InternetReadFile hRequest, API_bufStr, API_rsize, API_hsize
						if (API_hsize = 0) : break 
						p1 += strmid(API_bufStr, 0, API_hsize)
						await 0
					loop
				} else {
					//ヘッダの取得ができなかった場合
					API_statcode = -1
				}
			} else {
				//サーバへリクエスト送信できなかった場合
				API_statcode = -2
			}
			//Requestハンドルの破棄
			_InternetCloseHandle hRequest
		} else {
			//Requestハンドルを取得できなかった場合
			API_statcode = -3
		}
		//Connectハンドルの破棄
		_InternetCloseHandle hConnect
	} else {
		//Connectハンドルを取得できなかった場合
		API_statcode = -4
	}
return API_statcode
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
getBody
TwitterAPI操作命令実行後の結果を取得

%prm
()

%inst
TwitterAPI操作命令実行後の応答結果を返します。

%group
TwitterAPI操作関数

%*/
//------------------------------------------------------------
#defcfunc getBody
return ResponseBody
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
getHeader
TwitterAPI操作命令実行後のヘッダを取得

%prm
()

%inst
TwitterAPI操作命令実行後のヘッダを返します。

%group
TwitterAPI操作関数

%*/
//------------------------------------------------------------
#defcfunc getHeader
return ResponseHeader
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
TS_Init
TsubuyakiSoupの初期化

%prm
p1, p2, p3
p1 = 文字列      : ユーザエージェント
p2 = 文字列      : Consumer Key
p3 = 文字列      : Consumer Secret
p4 = 0～(30)     : タイムアウトの時間(秒)

%inst
TsubyakiSoupモジュールの初期化をします。Twitter操作命令の使用前に呼び出す必要があります。

p1にユーザエージェントを指定します。ユーザエージェントを指定していないとSearchAPIなどで厳しいAPI制限を受けることがあります。

p2にConsumer Keyを、p3にConsumer Secretを指定してください。Consumer KeyとConsumer Secretは、Twitterから取得する必要があります。詳しくは、リファレンスをご覧ください。

p4にはTwitterと通信する際のタイムアウトの時間を秒単位で指定してください。

%href
TS_End

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _TS_Init str p1, str p2, str p3, int p4
	//各種変数の初期化
	TS_RateLimit(0) = -1		//60分間にAPIを実行できる回数
	TS_RateLimit(1) = -1		//APIを実行できる残り回数
	TS_RateLimit(2) = -1		//リセットする時間
	TS_AccessToken = ""				//AccessToken
	TS_AccessTokenSecret = ""		//AccessTokenSecret
	TS_RequestToken = ""		//RequestToken
	TS_RquestTokenSecret = ""	//RequestTokenSecret
	TS_Consumer_Key = p2		//ConsumerKey
	TS_Consumer_Secret = p3		//ConsumerSecret
	TS_ScreenName = ""
	TS_UserID = 0.0
	TS_FormatType = "json"
	tmpInt = p4*1000
	//インターネットオープン
	TS_hInet = _InternetOpen( p1, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0)
	//INTERNET_OPTION_CONNECT_TIMEOUT  2
	_InternetSetOption TS_hInet, 2, varptr(tmpInt), 4
	//INTERNET_OPTION_HTTP_DECODING  65
	flag = 1
	_InternetSetOption TS_hInet, 65, varptr(flag), 4
return
#define global TS_Init(%1,%2,%3,%4=30) _TS_Init %1, %2, %3, %4
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
TS_End
TsubuyakiSoupの終了処理

%inst
TsubyakiSoupモジュールの終了処理を行ないます。
プログラム終了時に自動的に呼び出されるので明示的に呼び出す必要はありません。

%href
TS_Init

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc TS_End onexit
	//ハンドルの破棄
	if (hRequest) : _InternetCloseHandle hRequest
	if (hConnect) : _InternetCloseHandle hConnect
	if (TS_hInet) : _InternetCloseHandle TS_hInet
return
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
SetFormatType
取得フォーマットの設定

%prm
p1
p1 = 0～1(0)     : フラグ

%inst
TwitterAPI操作命令系で取得するデータのフォーマットを設定します。

p1には以下のフラグが設定できます。
    0 : JSON形式で取得
    1 : XML形式で取得

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _SetFormatType int p1
	TS_FormatType = "json"
	if p1 = 1 : TS_FormatType = "xml"
return
#define global SetFormatType(%1=0) _SetFormatType %1
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetAuthorizeAdress
アクセス許可を求めるURLを生成

%prm
()

%inst
ユーザにアクセス許可を求めるアドレスを生成し、戻り値として返します。

内部でTwitterと通信し、リクエストトークンを取得しています。リクエストトークンの取得に失敗した場合は、"Error"という文字列を返します。

%group
TwitterAPI操作関数

%*/
//------------------------------------------------------------
#defcfunc GetAuthorizeAdress
	// アクセストークン取得
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "oauth/request_token", Argument
	if stat != 200 : return "Error"
	// トークンの取り出し
	;request_token
	TokenStart = instr(ResponseBody, 0, "oauth_token=") + 12
	TokenEnd = instr(ResponseBody, TokenStart, "&")
	TS_RequestToken = strmid(ResponseBody, TokenStart, TokenEnd)
	;request_token_secret
	Token_SecretStart = instr(ResponseBody, 0, "oauth_token_secret=") + 19
	Token_SecretEnd = instr(ResponseBody, Token_SecretStart, "&")
	TS_RquestTokenSecret = strmid(ResponseBody, Token_SecretStart, Token_SecretEnd)
return "http://api.twitter.com/oauth/authorize?oauth_token="+ TS_RequestToken
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
SetAccessToken
AccessTokenとSecretを設定

%prm
p1, p2
p1 = 文字列      : Access Token
p2 = 文字列      : Access Secret

%inst
TsubuyakiSoupにAccess TokenとAccess Secretを設定します。

p1にAccess Tokenを、p2にAccess Secretを指定します。

このAccess TokenとAccess Secretは、GetAccessToken命令かGetxAuthToken命令で取得することができます。詳しくは、リファレンスをご覧ください。

%href
GetAccessToken
GetxAuthToken

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc SetAccessToken str p1, str p2
	TS_AccessToken = p1
	TS_AccessTokenSecret = p2
return
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
SetUserInfo
ユーザ情報を設定

%prm
p1, p2
p1 = 文字列      : ユーザ名（スクリーン名）
p2 = 0～         : ユーザID

%inst
TsubuyakiSoupにユーザ名（スクリーン名）とユーザIDを設定します。

p1にユーザ名（スクリーン名）を、p2にユーザIDを指定します。

このユーザ名（スクリーン名）とユーザIDは、GetAccessToken命令かGetxAuthToken命令を使用して取得してください。詳しくは、リファレンスをご覧ください。

%href
GetAccessToken
GetxAuthToken

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc SetUserInfo str p1, double p2
	TS_ScreenName = p1
	TS_UserID = p2
return
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetAccessToken
OAuthでAccessTokenとSecret取得

%prm
p1, p2, p3, p4
p1 = 変数        : Access Tokenを代入する変数
p2 = 変数        : Access Secretを代入する変数
p3 = 変数        : ユーザ情報を代入する変数
p4 = 文字列      : PINコード

%inst
TwitterAPI「oauth/access_token」を実行し、OAuth方式でAccess TokenとAccess Secretを取得します。

p1, p2にそれぞれAccess Token, Access Secretを代入する変数を指定してください。

p3には、ユーザ情報を代入する変数を指定してください。「ユーザID,ユーザ名」とカンマ区切りでユーザ情報が代入されます。

p4には、PINコードを指定してください。PINコードは、GetAuthorizeAdressで取得したURLにアクセスし、ユーザが「許可」ボタンを押したときに表示されます。詳しくは、リファレンスをご覧ください。

Access TokenとSecretは、一度取得すると何度も使用することができます（現在のTwitterの仕様では）。そのため、一度Access TokenとSecretを取得したら保存しておくことをおすすめします。
また、Access TokenとSecretはユーザ名とパスワードのようなものなので、暗号化して保存するなど管理には気をつけてください。OAuth/xAuthの詳しいことは、リファレンスをご覧ください。

%href
GetAuthorizeAdress
GetxAuthToken
SetAccessToken

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc GetAccessToken var p1, var p2, var p3, str p4
	sdim p1
	sdim p2
	sdim p3
	sdim Argument
	Argument(0) = "oauth_token="+ TS_RequestToken
	Argument(1) = "oauth_verifier="+ p4
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "oauth/access_token", Argument
	statcode = stat
	if statcode = 200  {
		//トークンの取り出し
		;request_token
		TokenStart = instr(ResponseBody, 0, "oauth_token=") + 12
		TokenEnd = instr(ResponseBody, TokenStart, "&")
		p1 = strmid(ResponseBody, TokenStart, TokenEnd)
		;request_token_secret
		TokenStart = instr(ResponseBody, 0, "oauth_token_secret=") + 19
		TokenEnd = instr(ResponseBody, TokenStart, "&")
		p2 = strmid(ResponseBody, TokenStart, TokenEnd)
		;User情報
		TokenStart = instr(ResponseBody, 0, "user_id=") + 8
		TokenEnd = instr(ResponseBody, TokenStart, "&")
		p3 = strmid(ResponseBody, TokenStart, TokenEnd) +","
		TokenStart = instr(ResponseBody, 0, "screen_name=") + 12
		TokenEnd = strlen(ResponseBody)
		p3 += strmid(ResponseBody, TokenStart, TokenEnd)
	}
return statcode
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetxAuthToken
xAuthでAccessTokenとSecret取得

%prm
p1, p2, p3, p4, p5
p1 = 変数        : Access Tokenを代入する変数
p2 = 変数        : Access Secretを代入する変数
p3 = 変数        : ユーザ情報を代入する変数
p4 = 文字列      : ユーザ名（スクリーン名）
p5 = 文字列      : パスワード

%inst
TwitterAPI「oauth/access_token」を実行し、xAuth方式でAccess TokenとAccess Secretを取得します。

p1, p2にそれぞれAccess Token, Access Secretを代入する変数を指定してください。

p3には、ユーザ情報を代入する変数を指定してください。「ユーザID,ユーザ名」とカンマ区切りでユーザ情報が代入されます。

p4にはTwitterでのユーザ名（スクリーン名）を、p5にはパスワードを指定してください。

認証方式にxAuthを使用するには、TwitterにxAuthの利用について申請をし、承認を受ける必要があります。詳しくは、リファレンスをご覧ください。

Access TokenとSecretは、一度取得すると何度も使用することができます（現在のTwitterの仕様では）。そのため、一度Access TokenとSecretを取得したら保存しておくことをおすすめします。
また、Access TokenとSecretはユーザ名とパスワードのようなものなので、暗号化して保存するなど管理には気をつけてください。詳しくは、リファレンスをご覧ください。

%href
GetAccessToken
SetAccessToken

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc GetxAuthToken var p1, var p2, var p3, str p4, str p5, local GRT_Password
	GRT_UserName = p4
	GRT_Password = p5
	p3 = ""
	//POST
	sdim Argument
	Argument(0) = "x_auth_mode=client_auth"
	Argument(1) = "x_auth_password=" + GRT_Password
	Argument(2) = "x_auth_username=" + GRT_UserName
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "oauth/access_token", Argument
	statcode = stat
	if statcode = 200  {
		//トークンの取り出し
		;oauth_token
		TokenStart = instr(ResponseBody, 0, "oauth_token=") + 12
		TokenEnd = instr(ResponseBody, TokenStart, "&")
		p1 = strmid(ResponseBody, TokenStart, TokenEnd)
		;oauth_token_secret
		TokenStart = instr(ResponseBody, 0, "oauth_token_secret=") + 19
		TokenEnd = instr(ResponseBody, TokenStart, "&")
		p2 = strmid(ResponseBody, TokenStart, TokenEnd)
		;User情報
		TokenStart = instr(ResponseBody, 0, "user_id=") + 8
		TokenEnd = instr(ResponseBody, TokenStart, "&")
		p3 = strmid(ResponseBody, TokenStart, TokenEnd) +","
		TokenStart = instr(ResponseBody, 0, "screen_name=") + 12
		TokenEnd = instr(ResponseBody, TokenStart, "&")
		p3 += strmid(ResponseBody, TokenStart, TokenEnd)
	}
return statcode
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetHomeTL
ホームタイムラインの取得

%prm
p1
p1 = 1～200(20)  : 取得する件数

%inst
TwitterAPI「statuses/home_timeline」を実行し、ホームタイムラインをSetFormatType命令で指定したフォーマットで取得します。

p1に取得する件数を指定してください。TwitterAPIの仕様上、指定できるのは200件までです。200以上を指定しても200件までしか取得できません。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%href
GetUserTL
GetMentions
GetRetweetByMe
GetRetweetToMe
GetRetweetOfMe

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetHomeTL int p1
	//件数
	sdim Argumet
	Argument(0) = "count=" + limit(p1,1,200)
	//GET
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "statuses/home_timeline."+ TS_FormatType, Argument
return stat
#define global GetHomeTL(%1=20) _GetHomeTL %1
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetUserTL
ユーザタイムラインの取得

%prm
p1, p2
p1 = 文字列      : ユーザ名（スクリーン名）
p2 = 1～200(20)  : 取得する件数

%inst
TwitterAPI「statuses/user_timeline」を実行し、ユーザタイムラインをSetFormatType命令で指定したフォーマットで取得します。

p1にタイムラインを取得したいユーザのユーザ名（スクリーン名）を指定してください。

p2に取得する件数を指定してください。TwitterAPIの仕様上、指定できるのは200件までです。200以上を指定しても200件までしか取得できません。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%href
GetHomeTL
GetMentions
GetRetweetByMe
GetRetweetToMe
GetRetweetOfMe

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetUserTL str p1, int p2
	//件数
	sdim Argument
	Argument(0) = "count=" + limit(p2, 1, 200)
	//GET
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "statuses/user_timeline/"+p1+"."+ TS_FormatType, Argument
return stat
#define global GetUserTL(%1,%2=20) _GetUserTL %1, %2
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetMentions
自分に対する言及の取得

%prm
p1
p1 = 1～200(20)  : 取得する件数

%inst
TwitterAPI「statuses/mentions」を実行し、自分に対する言及（「@xxxxx」を含むステータス）をSetFormatType命令で指定したフォーマットで取得します。

p1に取得する件数を指定してください。TwitterAPIの仕様上、指定できるのは200件までです。200以上を指定しても200件までしか取得できません。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%href
GetHomeTL
GetUserTL
GetRetweetByMe
GetRetweetToMe
GetRetweetOfMe

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetMentions int p1
	//カウント
	sdim Argument
	Argument(0) = "count=" + limit(p1,1,200)
	//GET
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "statuses/mentions."+ TS_FormatType, Argument
return stat
#define global GetMentions(%1=20) _GetMentions %1
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetRetweetByMe
自分が投稿したリツイートの取得

%prm
p1
p1 = 1～200      : 取得する件数

%inst
TwitterAPI「statuses/retweeted_by_me」を実行し、自分が投稿したリツイートをSetFormatType命令で指定したフォーマットで取得します。

p1に取得する件数を指定してください。TwitterAPIの仕様上、指定できるのは200件までです。200以上を指定しても200件までしか取得できません。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%href
GetHomeTL
GetUserTL
GetMentions
GetRetweetToMe
GetRetweetOfMe

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetRetweetByMe int p1
	//カウント
	sdim Argument
	Argument(0) = "count=" + limit(p1,1,200)
	//GET
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "statuses/retweeted_by_me."+ TS_FormatType, Argument
return stat
#define global GetRetweetByMe(%1=20) _GetRetweetByMe %1
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetRetweetToMe
自分のfriendsが投稿したリツイートの取得

%prm
p1
p1 = 1～200(20)  : 取得する件数

%inst
TwitterAPI「statuses/retweeted_to_me」を実行し、自分のfriendsが投稿したリツイートをSetFormatType命令で指定したフォーマットで取得します。

p1に取得する件数を指定してください。TwitterAPIの仕様上、指定できるのは200件までです。200以上を指定しても200件までしか取得できません。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%href
GetHomeTL
GetUserTL
GetMentions
GetRetweetByMe
GetRetweetOfMe

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetRetweetToMe int p1
	//カウント
	sdim Argument
	Argument(0) = "count=" + limit(p1,1,200)
	//GET
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "statuses/retweeted_to_me."+ TS_FormatType, Argument
return stat
#define global GetRetweetToMe(%1=20) _GetRetweetToMe %1
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetRetweetOfMe
リツイートされた自分の投稿を取得

%prm
p1
p1 = 1～200(20) : 取得する件数

%inst
TwitterAPI「statuses/retweets_of_me」を実行し、リツイートされた自分の投稿をSetFormatType命令で指定したフォーマットで取得します。

p1に取得する件数を指定してください。TwitterAPIの仕様上、指定できるのは200件までです。200以上を指定しても200件までしか取得できません。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%href
GetHomeTL
GetUserTL
GetMentions
GetRetweetByMe
GetRetweetToMe

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetRetweetOfMe int p1
	//カウント
	sdim Argument
	Argument(0) = "count=" + limit(p1,1,200)
	//GET
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "statuses/retweets_of_me."+ TS_FormatType, Argument
return stat
#define global GetRetweetOfMe(%1=20) _GetRetweetOfMe %1
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
Tweet
ツイートする

%prm
p1, p2
p1 = 文字列      : ツイートする文字列
p2 = 0～(0)      : 返信(reply)対象のステータスID

%inst
TwitterAPI「statuses/update」を実行し、Twitterへ投稿します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1にツイートする140字以内の文字列を指定してください。140字以上の場合、140字に丸めてからツイートされます。

p2に返信(reply)対象のステータスIDを指定することでどのステータスに対する返信かを明示できます。p2に0を指定するか省略した場合は、明示されません。
TwitterAPIの仕様上、存在しない、あるいはアクセス制限のかかっているステータスIDを指定した場合と、p1で指定した文字列に「@ユーザ名」が含まれない、あるいは@ユーザ名」で指定したユーザが存在しない場合は、無視されます。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用していますが、1日に1000回までという実行回数上限が設定されています(API以外からの投稿もカウント対象)。

%href
DelTweet
ReTweet

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _Tweet str p1, double p2
	tmpBuf = p1
	tmpStr = ""
	//１４０字に丸める
	if (mb_strlen(tmpBuf) > 140) {
		tmpBuf = mb_strmid(p1, 0,140)
	}
	//utf-8へ変換。
	sjis2utf8n tmpStr, tmpBuf
	//POST
	sdim Argument
	Argument(0) = "status="+ form_encode(tmpStr, 1)
	if p2 > 0 : Argument(1) = "in_reply_to_status_id="+ strf("%.0f",p2) 
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "statuses/update."+ TS_FormatType, Argument
return stat
#define global Tweet(%1, %2=0) _Tweet %1, %2
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
DelTweet
ツイートを削除する

%prm
p1
p1 = 0～         : 削除するステータスID

%inst
TwitterAPI「statuses/destroy」を実行し、指定されたステータスを削除します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1に削除するステータスIDを指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%href
Tweet
ReTweet

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc DelTweet double p1
	//POST
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "statuses/destroy/"+strf("%.0f",p1)+"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
ReTweet
リツイートする

%prm
p1
p1 = 0～         : リツイートするステータスID

%inst
TwitterAPI「statuses/retweet」を実行し、指定されたステータスをリツイートします。結果はSetFormatType命令で指定したフォーマットで取得します。

p1にリツイートするステータスIDを指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用していますが、1日に1000回までという実行回数上限が設定されています(API以外からの投稿もカウント対象)。

%href
Tweet
DelTweet

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc ReTweet double p1
	//POST
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "statuses/retweet/"+strf("%.0f",p1)+"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetDirectMessage
自分宛てのダイレクトメッセージの取得

%prm
p1
p1 = 1～200(20)  : 件数

%inst
TwitterAPI「direct_messages」を実行し、自分宛てのダイレクトメッセージの一覧をSetFormatType命令で指定したフォーマットで取得します。

p1に取得する件数を指定してください。TwitterAPIの仕様上、指定できるのは200件までです。200以上を指定しても200件までしか取得できません。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetDirectMessage int p1
	//カウント
	sdim Argument
	Argument(0) = "count=" + limit(p1,1,200)
	//GET
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "direct_messages."+ TS_FormatType, Argument
return stat
#define global GetDirectMessage(%1=20) _GetDirectMessage %1
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetDirectMessageSent
自分が送ったダイレクトメッセージの取得

%prm
p1
p1 = 1～200      : 件数

%inst
TwitterAPI「direct_messages/sent」を実行し、自分が送ったダイレクトメッセージの一覧をSetFormatType命令で指定したフォーマットで取得します。

p1に取得する件数を指定してください。TwitterAPIの仕様上、指定できるのは200件までです。200以上を指定しても200件までしか取得できません。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetDirectMessageSent int p1
	//カウント
	sdim Argument
	Argument(0) = "count=" + limit(p1,1,200)
	//GET
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "direct_messages/sent."+ TS_FormatType, Argument
return stat
#define global GetDirectMessageSent(%1=20) _GetDirectMessageSent %1
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
NewDirectMessage
ダイレクトメッセージを送信

%prm
p1, p2
p1 = 文字列      : ユーザ名（スクリーン名）
p2 = 文字列      : 本文

%inst
TwitterAPI「direct_messages/new」を実行し、指定されたユーザ宛にダイレクトメッセージを送信します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1に宛先のユーザ名（スクリーン名）を指定してください。

p2に本文を指定してください。本文は、140字以内にしてください。140字以上の場合は、140字以内に丸めて送信されます。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用していますが、1日に1000回までという実行回数上限が設定されています(API以外からの投稿もカウント対象)。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc NewDirectMessage str p1, str p2
	tmpBuf = p2
	tmpStr = ""
	//１４０字に丸める
	if (mb_strlen(tmpBuf) > 140) {
		tmpBuf = mb_strmid(p1, 0,140)
	}
	;utf-8へ変換。
	sjis2utf8n tmpStr, tmpBuf
	//POST
	sdim Argument
	Argument(0) = "text="+ form_encode(tmpStr, 1)
	Argument(1) = "user_name="+ p1
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "direct_messages/new."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
DelDirectMessage
ダイレクトメッセージを削除

%prm
p1
p1 = 0～         : ダイレクトメッセージID

%inst
TwitterAPI「direct_messages/destroy」を実行し、指定されたダイレクトメッセージを削除します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1に削除するダイレクトメッセージIDを指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc DelDirectMessage double p1
	//POST
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "direct_messages/destroy/"+strf("%.0f",p1)+"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetFriends
friendsの一覧を取得

%prm
p1, p2
p1 = 文字列("-1")  : カーソル
p2 = 文字列        : ユーザ名（スクリーン名）

%inst
TwitterAPI「statuses/friends」を実行し、指定されたユーザのfriendsの一覧をSetFormatType命令で指定したフォーマットで取得します。

p1にカーソルを指定してください。カーソルについては、リファレンスをご覧ください。

p2には、friendsの一覧を取得したいユーザのユーザ名（スクリーン名）を指定してください。省略した場合は、自分のfriendsの一覧を取得します。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetFriends str p1, str p2
	sdim Argument
	Argument(0) = "cursor="+ p1
	if (p2 != "") : Argument(1) = "screen_name="+ p2
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "statuses/friends."+ TS_FormatType, Argument
return stat
#define global GetFriends(%1="-1", %2="") _GetFriends %1, %2
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetFollowers
followersの一覧を取得

%prm
p1, p2
p1 = 文字列("-1")  : カーソル
p2 = 文字列        : ユーザ名（スクリーン名）

%inst
TwitterAPI「statuses/followers」を実行し、指定されたユーザのfollowersの一覧をSetFormatType命令で指定したフォーマットで取得します。

p1にカーソルを指定してください。カーソルについては、リファレンスをご覧ください。

p2には、followersの一覧を取得したいユーザのユーザ名（スクリーン名）を指定してください。省略した場合は、自分のfollowersの一覧を取得します。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetFollowers str p1, str p2
	sdim Argument
	Argument(0) = "cursor="+ p1
	if (p2 != "") : Argument(1) = "screen_name="+ p2
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "statuses/followers."+ TS_FormatType, Argument
return stat
#define global GetFollowers(%1="-1", %2="") _GetFollowers %1, %2
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
Follow
指定ユーザをフォロー

%prm
p1
p1 = 文字列      : ユーザ名（スクリーン名）

%inst
TwitterAPI「fiendships/create」を実行し、指定されたユーザをフォローします。結果はSetFormatType命令で指定したフォーマットで取得します。

p1にファローするユーザのユーザ名（スクリーン名）を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用していますが、1日に1000回までという実行回数上限が設定されています(API以外からの投稿もカウント対象)。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc Follow str p1
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "friendships/create/"+ p1 +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
Remove
指定ユーザをリムーブ

%prm
p1
p1 = 文字列      : ユーザ名（スクリーン名）

%inst
TwitterAPI「fiendships/destroy」を実行し、指定されたユーザをリムーブします。結果はSetFormatType命令で指定したフォーマットで取得します。

p1にリムーブするユーザのユーザ名（スクリーン名）を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc Remove str p1
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "friendships/destroy/"+ p1 +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
FriendShow
ユーザ間のfriend関係を調べる

%prm
p1, p2
p1 = 0～         : ユーザ名（スクリーン名）
p2 = 0～         : ユーザ名（スクリーン名）

%inst
TwitterAPI「friendships/show」を実行し、指定されたユーザ間のfriend関係を調べてSetFormatType命令で指定したフォーマットで取得します。

p1に調査対象のうち1人目のユーザ名（スクリーン名）を指定してください。省略した場合は、調査対象は自分自身になる。

p2に調査対象のうち2人目のユーザ名（スクリーン名）を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _FriendShow str p1, str p2
	sdim Argument
	if p1 = "" {
		Argument(0) = "target_screen_name="+ p2
	} else {
		Argument(0) = "source_screen_name="+ p1
		Argument(1) = "target_screen_name="+ p2
	}
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "friendships/show."+ TS_FormatType, Argument
return stat
#define global FriendShow(%1="", %2) _FriendShow %1, %2
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetFavorite
お気に入りの取得

%prm
p1, p2
p1 = 文字列      : ユーザ名（スクリーン名）
p2 = 1～(1)      : ページ数

%inst
TwitterAPI「favorites」を実行し、指定されたユーザのお気に入りに登録されているツイートをSetFormatType命令で指定したフォーマットで取得します。

p1にお気に入りを取得したいユーザのユーザ名（スクリーン名）を指定してください。

p2には取得するページ数を指定します。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetFavorite str p1, int p2
	sdim Argument
	Argument(0) = "page="+ p2
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "favorites/"+ p1 +"."+ TS_FormatType, Argument
return stat
#define global GetFavorite(%1,%2=1)  _GetFavorite %1, %2
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
AddFavorite
お気に入りに追加

%prm
p1
p1 = 0～         : ステータスID

%inst
TwitterAPI「favorites/create」を実行し、指定されたツイートをお気に入りに登録します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1にお気に入りに追加したいステータスIDを指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc AddFavorite double p1
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "favorites/create/"+ strf("%.0f",p1) +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
DelFavorite
お気に入りから削除

%prm
p1
p1 = 0～         : ステータスID

%inst
TwitterAPI「favorites/destroy」を実行し、指定されたツイートをお気に入りから削除します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1にお気に入りから削除したいステータスIDを指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc DelFavorite double p1
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "favorites/destroy/"+ strf("%.0f",p1) +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
AddBlock
ユーザをブロック

%prm
p1
p1 = 文字列      : ユーザ名（スクリーン名）

%inst
TwitterAPI「blocks/create」を実行し、指定されたユーザをブロックします。結果はSetFormatType命令で指定したフォーマットで取得します。

p1にブロックしたいユーザ名（スクリーン名）を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc AddBlock str p1
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "blocks/create/"+ p1 +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
DelBlock
ユーザをブロックから外す

%prm
p1
p1 = 文字列      : ユーザ名（スクリーン名）

%inst
TwitterAPI「blocks/destroy」を実行し、指定されたユーザをブロックから外します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1にブロックから外したいユーザ名（スクリーン名）を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc DelBlock str p1
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "blocks/destroy/"+ p1 +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
ExisistBlock
ユーザをブロックしているか調べる

%prm
p1
p1 = 文字列      : ユーザ名（スクリーン名）

%inst
TwitterAPI「blocks/exisits」を実行し、指定されたユーザをブロックしているか調べて、SetFormatType命令で指定したフォーマットで取得します。

p1にブロックしているか調べたいユーザ名（スクリーン名）を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc ExisistBlock str p1
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "blocks/exisits/"+ p1 +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetBlock
ブロックユーザの一覧を取得

%prm
p1
p1 = 1～(1)      : ページ数

%inst
TwitterAPI「blocks/blocking」を実行し、自分がブロックしているユーザの一覧をSetFormatType命令で指定したフォーマットで取得します。

p1に取得するページを指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetBlock int p1
	sdim Argument
	Argument(0) = "page="+ p1
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "blocks/blocking."+ TS_FormatType, Argument
return stat
#define global GetBlock(%1=1) _GetBlock %1
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetBlockIds
ブロックユーザの一覧(ID)を取得

%inst
TwitterAPI「blocks/blocking/ids」を実行し、自分がブロックしているユーザの一覧をSetFormatType命令で指定したフォーマットで取得します。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc GetBlockIds
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "blocks/blocking/ids."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
TwitterTest
Twitterの状態を調べる

%inst
TwitterAPI「help/test」を実行し、Twitterが正常に稼働しているか調べ、SetFormatType命令で指定したフォーマットで取得します。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc TwitterTest
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, "help/test."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
ReportSpam
ユーザをスパムとして報告

%prm
p1
p1 = 文字列      : ユーザ名（スクリーン名）

%inst
TwitterAPI「report_spam」を実行して、指定ユーザをスパマーであると報告し、ブロックします。結果はSetFormatType命令で指定したフォーマットで取得します。

p1にスパマーと報告するユーザのユーザ名（スクリーン名）を指定します。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc ReportSpam str p1
	sdim Argument
	Argument(0) = "id="+ p1
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, "report_spam."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
CreateList
リストを作成

%prm
p1, p2, p3
p1 = 文字列      : リスト名
p2 = 0～1(0)     : 公開範囲
p3 = 文字列      : 説明

%inst
TwitterAPIを実行し、新規にリストを作成します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1で指定した名前でリストを作成します。使用できるのは、英数字のみです。

p2でリストの公開範囲を指定できます。以下のフラグが設定できます。
    0 : 公開 (public)
    1 : 非公開 (private)

p3には、リストの説明を指定します。指定できる文字列の長さは、100字までです。100字を超えた場合は、命令側が100字に丸めてTwitterAPIの引数に指定します。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc CreateList str p1, int p2, str p3
	tmpBuf = p3
	tmpStr = ""
	//１００字に丸める
	if (mb_strlen(tmpBuf) > 100) {
		tmpStr = mb_strmid(p1, 0,100)
	}
	;utf-8へ変換。
	sjis2utf8n tmpStr, tmpBuf
	sdim Argument
	Argument(1) = "name="+ p1
	Argument(0) = "description="+ form_encode(tmpStr, 1)
	Argument(2) = "mode=public"
	if p2 = 1 : Argument(2) = "mode=private"
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, TS_ScreenName +"/lists."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
UpdateListName
リストの名前を変更

%prm
p1, p2
p1 = 文字列      : リスト名
p2 = 文字列      : 新しいリスト名

%inst
TwitterAPIを実行し、リストの名前を変更します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1にリストの名前を変更したいリスト名を指定してください。

p2に新しいリスト名を指定します。使用できるのは、英数字のみです。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc UpdateListName str p1, str p2
	sdim Argument
	Argument(0) = "name="+ p2
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, TS_ScreenName +"/lists/"+ p1 +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
UpdateListMode
リストの公開範囲を変更

%prm
p1, p2
p1 = 文字列      : リスト名
p2 = 0～1(0)     : 公開範囲

%inst
TwitterAPIを実行し、リストの公開範囲を変更します。結果はSetFormatType命令で指定したフォーマットで取得します。

変更をするリストの名前をp1に指定してください。

p2でリストを公開にするか非公開にするか指定できます。以下のフラグが設定できます。
    0 : 公開 (public)
    1 : 非公開 (private)

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc UpdateListMode str p1, int p2
	sdim Argument
	Argument(0) = "mode=public"
	if p2 = 1 : Argument(0) = "mode=private"
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, TS_ScreenName +"/lists/"+ p1 +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
UpdateListDescription
リストの説明文を変更

%prm
p1, p2, p3
p1 = 文字列      : リスト名
p2 = 0～1(0)     : 公開設定
p3 = 文字列      : 説明

%inst
TwitterAPIを実行し、リストの説明文を変更します。結果はSetFormatType命令で指定したフォーマットで取得します。

変更をするリストの名前をp1に指定してください。

p2には、リストの説明を指定します。指定できる文字列の長さは100字までです。100字を超えた場合は、命令側が100字に丸めてTwitterAPIの引数に指定します。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc UpdateListDescription str p1, str p2
	tmpBuf = p1
	tmpStr = ""
	//１００字に丸める
	if (mb_strlen(tmpBuf) > 100) {
		tmpBuf = mb_strmid(p1, 0,100)
	}
	;utf-8へ変換。
	sjis2utf8n tmpStr, tmpBuf
	//POST
	sdim Argument
	Argument(0) = "description="+ form_encode(tmpStr, 1)
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, TS_ScreenName +"/lists/"+ p1 +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetLists
リストの一覧を取得

%prm
p1, p2
p1 = 文字列("-1")  : カーソル
p2 = 文字列        : ユーザ名（スクリーン名）

%inst
TwitterAPIを実行し、指定したユーザのリストの一覧をSetFormatType命令で指定したフォーマットで取得します。自分自身のリストの一覧を取得する場合は、非公開のリストも含まれます。

p1にカーソルを指定してください。省略された場合は、TwitterAPIの引数に"-1"を渡します。カーソルの詳細についてはリファレンスをご覧ください。

p2にはリストの一覧を取得したいユーザのユーザ名（スクリーン名）を指定してください。省略された場合は、SetUserInfo命令で登録したユーザ名（スクリーン名）を使用します。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetLists str p1, str p2
	AddAdress = p2
	if p2 = "" : AddAdress = TS_ScreenName
	sdim Argument
	Argument(0) = "cursor="+ p1
	if p1 = "" : Argument(0) = "cursor=-1"
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, AddAdress +"/lists."+ TS_FormatType, Argument
return stat
#define global GetLists(%1="-1",%2="") _GetLists %1, $2
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetListInfo
リストの情報を取得

%prm
p1, p2
p1 = 文字列        : ユーザ名（スクリーン名）
p2 = 文字列        : リスト名

%inst
TwitterAPIを実行し、指定したユーザのリストの情報をSetFormatType命令で指定したフォーマットで取得します。自分自身のリストを指定した場合は、非公開のリストでも取得できます。

p1にはリストの情報を取得したいユーザのユーザ名（スクリーン名）を指定してください。省略された場合は、SetUserInfo命令で登録したユーザ名（スクリーン名）を使用します。

p2には情報を取得するリストのリスト名を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetListInfo str p1, str p2
	AddAdress = p1
	if p1 = "" : AddAdress = TS_ScreenName
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, AddAdress +"/lists/"+ p2 +"."+ TS_FormatType, Argument
return stat
#define global GetListInfo(%1="", %2) _GetListInfo %1, %2
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
DelList
リストを削除

%prm
p1
p1 = 文字列        : リスト名

%inst
TwitterAPIを実行し、指定したリストを削除します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1に削除したいリストのリスト名を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc DelList str p1
	sdim Argument
	Argument(0) = "_method=DELETE"
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, TS_ScreenName +"/lists/"+ p1 +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetListStatus
リストのタイムライン取得

%prm
p1, p2, p3
p1 = 文字列        : ユーザ名（スクリーン名）
p2 = 文字列        : リスト名
p3 = 1～200(20)    : 件数

%inst
TwitterAPIを実行し、指定したユーザのリストのタイムラインをSetFormatType命令で指定したフォーマットで取得します。

p1に対象ユーザのユーザ名（スクリーン名）を指定してください。省略された場合は、自分自身が対象になります。

p2には取得したいリストのリスト名を指定してください。

p3には取得する件数をしてします。TwitterAPIの仕様上、指定できるのは200件までです。200以上を指定しても200件までしか取得できません。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetListStatus str p1, str p2, int p3
	sdim Argument
	Argument(0) = "per_page="+ limit(p3, 1, 200)
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, p1 +"/lists/"+ p2 +"/statuses."+ TS_FormatType, Argument
return stat
#define global GetListStatus(%1=TS_ScreenName@TsubuyakiSoup,%2,%3=20) _GetListStatus %1, %2, %3
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetEntryList
フォローされてるリストの一覧を取得

%prm
p1, p2
p1 = 文字列("-1")  : カーソル
p2 = 文字列        : ユーザ名（スクリーン名）

%inst
TwitterAPIを実行し、指定したユーザがフォローされているリストの一覧をSetFormatType命令で指定したフォーマットで取得します。

p1にカーソルを指定してください。省略された場合は、TwitterAPIの引数に"-1"を渡します。カーソルの詳細についてはリファレンスをご覧ください。

p2には対象ユーザのユーザ名（スクリーン名）を指定してください。省略された場合は、SetUserInfo命令で登録したユーザ名（スクリーン名）を使用します。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetEntryList str p1, str p2
	AddAdress = p2
	if p2 = "" : AddAdress = TS_ScreenName
	sdim Argument
	Argument(0) = "cursor="+ p1
	if p1 = "" : Argument(0) = "cursor=-1"
	RESTAPI ResopnseBody, ResponseHeader, METHOD_GET, AddAdress +"/lists/memberships."+ TS_FormatType, Argument
return stat
#define global GetEntryList(%1="-1",%2="") _GetEntryList %1, %2
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetFollowList
フォローしているリストの一覧を取得

%prm
p1, p2
p1 = 文字列("-1")  : カーソル
p2 = 文字列        : ユーザ名（スクリーン名）

%inst
TwitterAPIを実行し、指定したユーザがフォローされているリストの一覧をSetFormatType命令で指定したフォーマットで取得します。

p1にカーソルを指定してください。省略された場合は、TwitterAPIの引数に"-1"を渡します。カーソルの詳細についてはリファレンスをご覧ください。

p2には対象ユーザのユーザ名（スクリーン名）を指定してください。省略された場合は、SetUserInfo命令で登録したユーザ名（スクリーン名）を使用します。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetFollowList str p1, str p2
	AddAdress = p2
	if p2 = "" : AddAdress = TS_ScreenName
	sdim Argument
	Argument(0) = "cursor="+ p1
	if p1 = "" : Argument(0) = "cursor=-1"
	RESTAPI ResopnseBody, ResponseHeader, METHOD_GET, AddAdress +"/lists/subscriptions."+ TS_FormatType, Argument
return stat
#define global GetFollowList(%1="-1",%2="") _GetFollowList %1, %2
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetListMembers
リストのメンバーの一覧

%prm
p1, p2, p3
p1 = 文字列("-1")  : カーソル
p2 = 文字列        : ユーザ名（スクリーン名）
p2 = 文字列        : リスト名

%inst
TwitterAPIを実行し、指定したユーザのリストがフォローしているユーザの一覧をSetFormatType命令で指定したフォーマットで取得します。

p1にカーソルを指定してください。省略された場合は、TwitterAPIの引数に"-1"を渡します。カーソルの詳細についてはリファレンスをご覧ください。

p2には、対象ユーザのユーザ名（スクリーン名）を指定してください。

p3には、一覧を取得したいリストのリスト名を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetListMembers str p1, str p2, str p3
	sdim Argument
	Argument(0) = "cursor="+ p1
	if p1 = "" : Argument(0) = "cursor=-1"
	//GET
	RESTAPI ResopnseBody, ResponseHeader, METHOD_GET, p2 +"/"+ p3 +"/members."+ TS_FormatType, Argument
return stat
#define global GetListMembers(%1="-1",%2,%3) _GetListMembers %1, %2, %3
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
AddListMember
リストにメンバーを追加

%prm
p1, p2
p1 = 文字列        : リスト名
p2 = 文字列        : ユーザ名（スクリーン名）

%inst
TwitterAPIを実行し、指定したリストにメンバーを追加します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1には追加先リストのリスト名を指定してください。

p2には、追加するユーザのユーザ名（スクリーン名）を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc AddListMember str p1, str p2
	sdim Argument
	Argument(0) = "id="+ p2
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, TS_ScreenName +"/"+ p1 +"/members."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
DelListMember
リストからメンバーを削除

%prm
p1, p2
p1 = 文字列        : リスト名
p2 = 文字列        : ユーザ名（スクリーン名）

%inst
TwitterAPIを実行し、指定したリストからメンバーを削除します。結果はSetFormatType命令で指定したフォーマットで取得します。

p1には削除元リストのリスト名を指定してください。

p2には、削除するユーザのユーザ名（スクリーン名）を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc DelListMember str p1, str p2
	sdim Argument
	Argument(0) = "id="+ p2
	Argument(1) = "_method=DELETE"
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, TS_ScreenName +"/"+ p1 +"/members."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
IsListMember
リストのメンバーか調べる

%prm
p1, p2, p3
p1 = 文字列        : ユーザ名（スクリーン名）
p2 = 文字列        : リスト名
p3 = 文字列        : ユーザ名（スクリーン名）

%inst
TwitterAPIを実行し、指定したユーザが、指定したリストのメンバーであるかどうかを調べます。結果はSetFormatType命令で指定したフォーマットで取得します。
リストのメンバーの場合は、そのユーザに関する情報が返ります。

p1に対象リストの作成者のユーザ名（スクリーン名）を指定してください。

p2には、対象リストのリスト名を指定してください。

p3には、対象ユーザのユーザ名を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc IsListMember str p1, str p2, str p3
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, p1 +"/"+ p2 +"/members/"+ p3 +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
GetListFollowers
リストのフォロワーの一覧

%prm
p1, p2, p3
p1 = 文字列("-1")  : カーソル
p2 = 文字列        : ユーザ名（スクリーン名）
p2 = 文字列        : リスト名

%inst
TwitterAPIを実行し、指定したユーザのリストをフォローしているユーザの一覧をSetFormatType命令で指定したフォーマットで取得します。

p1にカーソルを指定してください。省略された場合は、TwitterAPIの引数に"-1"を渡します。カーソルの詳細についてはリファレンスをご覧ください。

p2には、対象ユーザのユーザ名（スクリーン名）を指定してください。

p3には、一覧を取得したいリストのリスト名を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc _GetListFollowers str p1, str p2, str p3
	sdim Argument
	Argument(0) = "cursor="+ p1
	if p1 = "" : Argument(0) = "cursor=-1"
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, p2 +"/"+ p3 +"/subscribers."+ TS_FormatType, Argument
return stat
#define global GetListFollowers(%1="-1",%2,%3) _GetListFollowers %1, %2, %3
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
FollowList
リストをフォロー

%prm
p1, p2
p1 = 文字列        : ユーザ名（スクリーン名）
p2 = 文字列        : リスト名

%inst
TwitterAPIを実行し、指定したリストをフォローします。結果はSetFormatType命令で指定したフォーマットで取得します。

p1に対象リストの作成者のユーザ名（スクリーン名）を指定してください。

p2には、フォローするリストのリスト名を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc FollowList str p1, str p2
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, p1 +"/"+ p2 +"/subscribers."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
RemoveList
リストをリムーブ

%prm
p1, p2
p1 = 文字列        : ユーザ名（スクリーン名）
p2 = 文字列        : リスト名

%inst
TwitterAPIを実行し、指定したリストをフォローします。結果はSetFormatType命令で指定したフォーマットで取得します。

p1に対象リストの作成者のユーザ名（スクリーン名）を指定してください。

p2には、リムーブするリストのリスト名を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象外のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc RemoveList str p1, str p2
	sdim Argument
	Argument(0) = "_method=DELETE"
	RESTAPI ResponseBody, ResponseHeader, METHOD_POST, p1 +"/"+ p2 +"/subscribers."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
IsListFollower
リストのフォロワーか調べる

%prm
p1, p2, p3
p1 = 文字列        : ユーザ名（スクリーン名）
p2 = 文字列        : リスト名
p3 = 文字列        : ユーザ名（スクリーン名）

%inst
TwitterAPIを実行し、指定したユーザが、指定したリストのフォロワーであるかどうかを調べます。結果はSetFormatType命令で指定したフォーマットで取得します。
リストのフォロワーの場合は、そのユーザに関する情報が返ります。

p1に対象リストの作成者のユーザ名（スクリーン名）を指定してください。

p2には、対象リストのリスト名を指定してください。

p3には、対象ユーザのユーザ名を指定してください。

TwitterAPIを実行した際のステータスコードはシステム変数statに代入されます。
実行して返ってきた応答は、getBody関数とgetHeader関数で参照することができます。

API制限適用対象のAPIを使用しています。

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc IsListFollower str p1, str p2, str p3
	sdim Argument
	RESTAPI ResponseBody, ResponseHeader, METHOD_GET, p1 +"/"+ p2 +"/subscribers/"+ p3 +"."+ TS_FormatType, Argument
return stat
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
RateLimit
API制限状況を返す

%prm
(p1, p2)
p1 = 0～2        : 取得するデータの種類
p2 = 0～1        : 取得する方法

%inst
API制限状況を返します。

p1に取得するデータの種類を指定します。下記のフラグが設定できます。
    0 : 60分間にAPIを実行できる回数
    1 : APIを実行できる残り回数
    2 : API実行回数がリセットされる時間(UTC)

p2には取得する方法を指定します。下記のフラグが設定できます。
    0 : API(rate_limit_status)を実行し取得
    1 : 最後にAPIを実行した際のヘッダから取得

p2に 1 を指定した場合でも、この関数使用前にTwitterAPIを実行していなかったときは、TwitterAPI「rate_limit_status」を使用します。

API制限適用対象外のAPIを使用しています。（API使用時）

%group
TwitterAPI操作関数

%*/
//------------------------------------------------------------
#defcfunc RateLimit int p1, int p2
	//引数のチェック
	DataKind = p1
	if ((p1 < 0) or (p1 > 2)) : DataKind = 0
	//API(rate_limit_status)を実行
	if ( (p2 != 1) or (TS_RateLimit(0) = -1) ) {
		sdim Argument
		RESTAPI LocalBody, LocalHeader, METHOD_GET, "account/rate_limit_status.xml", Argument
		statcode = stat
		if statcode = 200 {
			newcom oDom,"Microsoft.XMLDOM"
			oDom("async")="False"
			oDom->"loadXML" LocalBody
			oRoot = oDom("documentElement")
			if (varuse(oRoot)) {
				//60分間にAPIを実行できる回数
				comres RateLimitElement
				oDom->"getElementsByTagName" "hourly-limit"
				node = RateLimitElement("item",0)
				TS_RateLimit(0) = int(node("text"))
				//APIを実行できる残り回数
				comres RateLimitElement
				oDom->"getElementsByTagName" "remaining-hits"
				node = RateLimitElement("item",0)
				TS_RateLimit(1) = int(node("text"))
				//API実行回数がリセットされる時間
				comres RateLimitElement
				oDom->"getElementsByTagName" "reset-time-in-seconds"
				node = RateLimitElement("item",0)
				TS_RateLimit(2) = int(node("text"))
				//後処理
				delcom node
				delcom RateLimitElement
				delcom oRoot
			}
			delcom oDom
		}
	}
return TS_RateLimit(DataKind)
//============================================================




//============================================================
/*  [HDL symbol infomation]

%index
TwitterSearch
ステータスを検索

%prm
p1
p1 = 配列      : APIに添加する引数を代入した文字列配列

%inst
SearchAPI「search」を実行し、Twitter内のステータスを検索して、検索結果をJSON形式で取得します。

SearchAPIに渡す引数を文字列型の配列にしてp1に指定します。
例えば、API"search"に引数"q=hsp"と"rpp=50"を指定して、"hsp"が含まれたステータスを検索し、50件取得するとします。
    Argument(0) = "q=hsp"
    Argument(1) = "rpp=50"
    TwitterSearch Argument

TS_Initでユーザエージェントを指定していない場合、厳しいAPI制限を受けることがあります。

%href
SearchAPI

%group
TwitterAPI操作命令

%*/
//------------------------------------------------------------
#deffunc TwitterSearch array p1
	SearchAPI ResponseBody, ResponseHeader, "search.json", p1
return stat
//============================================================



//============================================================
/*  [HDL symbol infomation]

%index
json_sel
JSON形式の文字列を選択

%prm
p1
p1 = JSON形式の文字列

%inst
JSON形式の文字列を選択します。

選択後、json_unsel命令を処理するまでjson_val関数、json_length関数の対象となります。

%href
json_val
json_length
json_unsel

%group
JSONパーサ

%*/
//------------------------------------------------------------
#deffunc json_sel str p1
	if vartype(mssc) != vartype("comobj") {
		newcom mssc, "MSScriptControl.ScriptControl"
		mssc("Language") = "JScript"
	}
	sdim tmp, strlen(p1)+1
	sdim jsontext, strlen(p1)+1
	tmp = p1
	jsontext = utf8n2sjis(tmp)
	sdim tmp, 0
	mssc -> "addCode" "obj = "+ jsontext +";"
return
//============================================================



//============================================================
/*  [HDL symbol infomation]

%index
json_val
指定した配列の要素の内容を返す

%prm
p1
p1 = 要素の位置

%inst
p1で指定された要素の内容を返します。

%href
json_sel
json_length
json_unsel

%group
JSONパーサ

%*/
//------------------------------------------------------------
#defcfunc json_val str p1
	comres result
	mssc -> "Eval" "obj"+ p1 +" === null"
	if (result == -1) : return ""
	mssc -> "Eval" "obj"+ p1
return result
//============================================================



//============================================================
/*  [HDL symbol infomation]

%index
json_length
配列の要素数を返す

%prm
p1
p1 = 要素の位置

%inst
p1で指定されたオブジェクトの要素数を返します。

%href
json_sel
json_val
json_unsel

%group
JSONパーサ

%*/
//------------------------------------------------------------
#defcfunc json_length str p1
	comres result
	mssc -> "Eval" "obj"+ p1 +".length"
return result
//============================================================



//============================================================
/*  [HDL symbol infomation]

%index
json_unsel
JSON形式の文字列の選択を解除する

%prm


%inst
json_selで指定されたJSON形式の文字列をパース対象から外します。

%href
json_sel
json_val
json_length

%group
JSONパーサ

%*/
//------------------------------------------------------------
#deffunc json_unsel
	sdim jsontext,0
return
//============================================================


#global





// 文字列操作モジュール
#module mod_string

#uselib "kernel32.dll"
#cfunc _MultiByteToWideChar "MultiByteToWideChar" int, int, sptr, int, int, int

/*------------------------------------------------------------*/
//1バイト・2バイト判定
//
//	Is_Byte(p1)
//		p1...判別文字コード
//		[0.1byte/1,2byte]
//

#defcfunc Is_Byte int p1
return (p1>=129 and p1<=159) or (p1>=224 and p1<=252)
/*------------------------------------------------------------*/

#defcfunc mb_strlen str p1
return _MultiByteToWideChar(0, 0, p1, -1, 0, 0)-1


#deffunc SortString array p1
	loopMax = length(p1) - 1
	repeat loopMax
		repeat loopMax - cnt
			a_pos = 0
			b_pos = 0
			elm_pos = loopMax - cnt
			a_len = strlen(p1(elm_pos))
			b_len = strlen(p1(elm_pos-1))
			if (a_len < b_len) { StrLenMin = a_len : Longer = 0 } else { StrLenMin = b_len : Longer = 1 }
			repeat StrLenMin
				a_buf = peek( p1(elm_pos), a_pos)
				if (Is_Byte(a_buf)) : a_buf = wpeek(p1(elm_pos), a_pos) : a_pos++
				a_pos++
				b_buf = peek( p1(elm_pos-1), b_pos)
				if (Is_Byte(b_buf)) : b_buf = wpeek(p1(elm_pos-1), b_pos) : b_pos++
				b_pos++
				if a_buf > b_buf : break
				if a_buf < b_buf : buf = p1(elm_pos) : p1(elm_pos) = p1(elm_pos-1) : p1(elm_pos-1) = buf
			loop
			if (a_buf = b_buf) and (Longer = 0) : buf = p1(elm_pos) : p1(elm_pos) = p1(elm_pos-1) : p1(elm_pos-1) = buf
		loop
	loop
return


/*------------------------------------------------------------*/
//半角・全角含めた文字数を取り出す
//
//	mb_strmid(p1, p2, p3)
//		p1...取り出すもとの文字列が格納されている変数名
//		p2...取り出し始めのインデックス
//		p3...取り出す文字数
//

#defcfunc mb_strmid var p1, int p2, int p3
	if vartype != 2 : return ""
	s_size = strlen(p1)
	trim_start = 0
	trim_num = 0
	repeat p2
		if (Is_Byte(peek(p1,trim_start))) : trim_start++
		trim_start++
	loop
	repeat p3
		if (Is_Byte(peek(p1,trim_start+trim_num))) : trim_num++
		trim_num++
	loop
return strmid(p1,trim_start,trim_num)


//p2 半角スペースの処理  0 : '&'  1 : '%20'
#defcfunc form_encode str p1, int p2
/*
09 az AZ - . _ ~
はそのまま出力
*/
fe_str = p1
fe_p1Long = strlen(p1)
sdim fe_val, fe_p1Long*3
repeat fe_p1Long
	fe_flag = 0
	fe_tmp = peek(fe_str, cnt)
	if (('0' <= fe_tmp)&('9' >= fe_tmp)) | (('A' <= fe_tmp)&('Z' >= fe_tmp)) | (('a' <= fe_tmp)&('z' >= fe_tmp)) | (fe_tmp = '-') | (fe_tmp = '.') | (fe_tmp = '_') | (fe_tmp = '~') :{
		poke fe_val, strlen(fe_val), fe_tmp
	} else {
		if fe_tmp = ' ' {
			if p2 = 0 : fe_val += "&"
			if p2 = 1 : fe_val += "%20"	//空白処理
		} else {
			fe_val += "%" + strf("%02X",fe_tmp)
		}
	}
loop
return fe_val


//ランダムな文字列を発生させる
//p1からp2文字まで33-
#defcfunc RandomString int p1, int p2
;randomize
RS_Strlen = rnd(p2-p1+1) + p1
sdim RS_val, RS_Strlen
repeat RS_Strlen
	RS_rnd = rnd(3)
	if RS_rnd = 0 : RS_s = 48 + rnd(10)
	if RS_rnd = 1 : RS_s = 65 + rnd(26)
	if RS_rnd = 2 : RS_s = 97 + rnd(26)
	poke RS_val, cnt, RS_s
loop
return RS_val

//BASE64へ変換
#defcfunc Base64Encode str p1
	buf = p1
	bufSize = strlen(buf)
	val = ""
	B64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	cc = 0
	frac = bufSize\3
	repeat bufSize/3
		repeat 3
			b(cnt) = peek(buf, cc*3+cnt)
		loop
		val += strmid(B64Table, (b(0) >> 2), 1)
		val += strmid(B64Table, ((b(0) & 3) << 4) + (b(1) >> 4), 1)
		val += strmid(B64Table, ((b(1) & 15) << 2) + (b(2) >> 6), 1)
		val += strmid(B64Table, (b(2) & 63), 1)
		cc++
	loop
	//端数分
	if (frac) {
		memexpand buf, bufSize+3
		repeat 3
			b(cnt) = peek(buf, cc*3+cnt)
		loop
		val += strmid(B64Table, b(0) >> 2, 1)
		if (frac >= 1) : val += strmid( B64Table, ((b(0) & %00000011) << 4) + (b(1) >> 4), 1)
		if (frac >= 2) : val += strmid( B64Table, ((b(1) & %00001111) << 2) + (b(2) >> 6), 1)
	}
	repeat (4-(strlen(val)\4))\4
		val += "="
	loop
return val

#global

