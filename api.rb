require 'sinatra'
require 'jwt'
require 'httpclient'

post '/posts' do
  # JWT
  token = request.env['HTTP_AUTHORIZATION'].gsub('Bearer ', '')

  # キーID
  kid = JWT.decode(token, nil, false)[1]['kid']

  # Googleのpublickeyの置き場所
  JWKS_URI = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'

  # Googleのpublickey(証明書)取得
  res = JSON.parse(HTTPClient.new.get(JWKS_URI).body)
  cer = OpenSSL::X509::Certificate.new(res[kid])

  # publickey抽出
  pub_key = cer.public_key

  # 署名の検証
  begin
    # publickeyでdecode
    decoded_token = JWT.decode(token, pub_key, true, { algorithm: 'RS256' })

    payload = decoded_token[0]

    # 現在のUNIXTIME
    now = Time.now.to_i

    # 確認項目: https://firebase.google.com/docs/auth/admin/verify-id-tokens?hl=ja#web
    # 有効期限
    exp = payload['exp'] >= now
    # 発行時
    iat = payload['iat'] <= now
    # 対象
    aud = payload['aud'] == 'benkyo-83021'
    # 発行元
    iss = payload['iss'] == 'https://securetoken.google.com/benkyo-83021'
    # 件名
    sub = (payload['sub'] == payload['user_id'] || payload['sub'] != '')
    # 認証時間
    auth_time = payload['auth_time'] <= now

    unless exp && iat && aud && iss && sub && auth_time
      raise JWT::VerificationError
    end

  rescue JWT::VerificationError
    headers 'Access-Control-Allow-Origin' => '*'
    halt 401, '立ち去れ!'
  end

  headers 'Access-Control-Allow-Origin' => '*'
  'success'
end

# cors用
options '/posts' do
  headers \
  'Access-Control-Allow-Origin' => '*',
  'Access-Control-Allow-Methods' => 'POST, OPTIONS',
  'Access-Control-Allow-Headers' => 'Authorization, Content-Type',
  'Access-Control-Max-Age' => 86400
  status 204
end
