<?php
// Offline harness: stubs for OPNsense classes, fake provider, real library + php-jwt.
namespace OPNsense\Auth { class OIDC { public $oidcProviderUrl='https://idp.test/app/.well-known/openid-configuration'; public $oidcClientId='client-1'; public $oidcClientSecret='s3cret-client-secret-value'; } }
namespace OPNsense\Mvc {
  class Session { public $d=[]; function get($k,$def=null){return $this->d[$k]??$def;} function set($k,$v){$this->d[$k]=$v;} function remove($k){unset($this->d[$k]);} }
  class Request { function getScheme(){return 'https';} function getHeader($h){return 'fw.test';} }
  class Response { public $loc=null; function redirect($u){$this->loc=$u;} }
  class Controller { public $session,$request,$response; function __construct(){$this->session=new Session;$this->request=new Request;$this->response=new Response;} }
}
namespace T {
require __DIR__.'/Oidc/OidcClient.php';
use OPNsense\Oidc\OidcClient; use Firebase\JWT\JWT;

$priv = openssl_pkey_new(['private_key_bits'=>2048,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);
$d = openssl_pkey_get_details($priv)['rsa'];
$b64 = fn($s)=>rtrim(strtr(base64_encode($s),'+/','-_'),'=');
$JWKS = json_encode(['keys'=>[['kty'=>'RSA','kid'=>'k1','use'=>'sig','n'=>$b64($d['n']),'e'=>$b64($d['e'])]]]);
$JWKS0 = $JWKS;
$other = openssl_pkey_new(['private_key_bits'=>2048,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);
$ISS='https://idp.test/app/';
$DISC=json_encode(['issuer'=>$ISS,'authorization_endpoint'=>$ISS.'authorize','token_endpoint'=>$ISS.'token','userinfo_endpoint'=>$ISS.'userinfo','jwks_uri'=>$ISS.'jwks','id_token_signing_alg_values_supported'=>['RS256'],'code_challenge_methods_supported'=>['S256']]);

class TC extends OidcClient {
  public $tokenCalls=0; public $idToken='';
  protected function fetchURL(string $url, ?string $post_body = null, array $headers = []) {
    global $JWKS,$DISC; if (str_ends_with($url,'/jwks')) return $JWKS; if (str_contains($url,'.well-known')) return $DISC; throw new \Exception("unexpected fetch $url"); }
  protected function requestTokens(string $code, array $headers = []) { $this->tokenCalls++; return (object)['id_token'=>$this->idToken,'access_token'=>'at-123','token_type'=>'Bearer']; }
  public function seed($state,$nonce){ $this->setSessionKey('openid_connect_state',$state); $this->setSessionKey('openid_connect_nonce',$nonce); }
  public function leftovers(){ return array_keys(array_filter([$this->getSessionKey('openid_connect_state'),$this->getSessionKey('openid_connect_nonce'),$this->getSessionKey('openid_connect_code_verifier')], fn($v)=>$v!==false)); }
}

function tok(array $claims, $key, string $alg='RS256', ?string $kid='k1') { return JWT::encode($claims, $key, $alg, $kid); }
function run(string $name, callable $mkToken, bool $expectOk, ?array $req=null, ?string $jwks=null) {
  global $ISS,$JWKS,$JWKS0; $JWKS=$jwks??$JWKS0; $c=new TC(new \OPNsense\Auth\OIDC, new \OPNsense\Mvc\Controller, 'fw.test');
  $c->seed('state-abc','nonce-xyz'); $c->idToken=$mkToken();
  $_REQUEST = $req ?? ['code'=>'code-1','state'=>'state-abc'];
  try { $ok=$c->authenticate(); $res=$ok?'ACCEPT':'false'; } catch (\Throwable $e) { $ok=false; $res='REJECT: '.substr($e->getMessage(),0,70); }
  $pass = ($ok===$expectOk);
  printf("%-4s %-38s %-50s tokenCalls=%d leftovers=%s\n", $pass?'PASS':'FAIL', $name, $res, $c->tokenCalls, json_encode($c->leftovers()));
  return $pass;
}
$now=time(); $base=['iss'=>$ISS,'aud'=>'client-1','sub'=>'u-1','nonce'=>'nonce-xyz','iat'=>$now,'exp'=>$now+300];
$w = fn($over,$drop=[]) => array_diff_key(array_merge($base,$over), array_flip($drop));
$r=[];
$r[]=run('valid RS256 token', fn()=>tok($base,$priv), true);
$r[]=run('HS256 signed with client secret', function() use ($base,$b64){ $h=$b64(json_encode(['alg'=>'HS256','typ'=>'JWT','kid'=>'k1'])); $p=$b64(json_encode($base)); return "$h.$p.".$b64(hash_hmac('sha256',"$h.$p",'s3cret-client-secret-value',true)); }, false);
$r[]=run('alg none (unsigned)', fn()=>$b64('{"alg":"none","kid":"k1"}').'.'.$b64(json_encode($base)).'.', false);
$r[]=run('signed by a different key', fn()=>tok($base,$other), false);
$r[]=run('unknown kid', fn()=>tok($base,$priv,'RS256','k9'), false);
$r[]=run('tampered payload', function() use ($base,$priv,$b64){ $t=explode('.',tok($base,$priv)); $t[1]=$b64(json_encode(array_merge($base,['sub'=>'admin']))); return implode('.',$t); }, false);
$r[]=run('missing nonce', fn()=>tok($w([],['nonce']),$priv), false);
$r[]=run('wrong nonce', fn()=>tok($w(['nonce'=>'other']),$priv), false);
$r[]=run('missing exp', fn()=>tok($w([],['exp']),$priv), false);
$r[]=run('expired (10 min ago)', fn()=>tok($w(['exp'=>$now-600]),$priv), false);
$r[]=run('missing iat', fn()=>tok($w([],['iat']),$priv), false);
$r[]=run('iat 1h in future', fn()=>tok($w(['iat'=>$now+3600]),$priv), false);
$r[]=run('wrong audience', fn()=>tok($w(['aud'=>'someone-else']),$priv), false);
$r[]=run('wrong issuer', fn()=>tok($w(['iss'=>'https://evil.test/']),$priv), false);
$r[]=run('azp is another client', fn()=>tok($w(['azp'=>'client-2']),$priv), false);
$r[]=run('multi-aud without azp', fn()=>tok($w(['aud'=>['client-1','x']]),$priv), false);
$r[]=run('bad state (code not redeemed)', fn()=>tok($base,$priv), false, ['code'=>'code-1','state'=>'wrong']);
$r[]=run('array code param', fn()=>tok($base,$priv), false, ['code'=>['x'],'state'=>'state-abc']);
$r[]=run('oversized token', fn()=>str_repeat('a',20000).'.b.c', false);
// JWKS hygiene: unsupported / encryption keys are skipped, not fatal, and never verify.
$sig = json_decode($JWKS0,true)['keys'][0];
$okp = ['kty'=>'OKP','crv'=>'X25519','kid'=>'x1','x'=>$b64(random_bytes(32))];
$encSame = array_merge($sig, ['use'=>'enc']);
$r[]=run('JWKS also has OKP X25519 + EC keys', fn()=>tok($base,$priv), true, null, json_encode(['keys'=>[$okp, ['kty'=>'EC','crv'=>'P-999','kid'=>'e1','x'=>'AA','y'=>'AA'], $sig]]));
$r[]=run('only key is use=enc (same RSA key)', fn()=>tok($base,$priv), false, null, json_encode(['keys'=>[$encSame]]));
$r[]=run('key_ops without verify', fn()=>tok($base,$priv), false, null, json_encode(['keys'=>[array_merge($sig,['key_ops'=>['encrypt']])]]));
$r[]=run('JWKS only unsupported keys', fn()=>tok($base,$priv), false, null, json_encode(['keys'=>[$okp]]));
// Callback host vetting (redirect_uri is built from the result).
$names = ['fw.test', 'fw-alt.test', '192.0.2.1'];
foreach ([['fw.test', 'fw.test'], ['FW.Test', 'fw.test'], ['fw.test:8443', 'fw.test:8443'], ['192.0.2.1', '192.0.2.1'],
          ['evil.test', null], ['fw.test.evil.test', null], ['evil.test#@fw.test', null], ['fw.test/x', null],
          ['fw.test:99999', null], ['', null], ['fw.test:', null], ["fw.test\r\nX: y", null]] as [$in, $want]) {
  $got = OidcClient::vetHost($in, $names); $ok = $got === $want; $r[] = $ok;
  printf("%-4s %-38s %-50s\n", $ok?'PASS':'FAIL', 'vetHost '.json_encode($in), json_encode($got));
}
echo (in_array(false,$r,true)?"SOME FAILED":"ALL PASSED"), " (".count($r)." cases)\n";
}
