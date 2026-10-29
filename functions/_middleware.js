// ============================================================
// Basic 認証（Cloudflare Pages Functions のミドルウェア）
//   すべてのページ・ファイルを返す前にこの処理が動き、
//   ユーザー名とパスワードが正しいときだけ中身を返す。
//   ユーザー名・パスワードはコードに書かず、Cloudflare の環境変数から読む。
//     BASIC_AUTH_USER … ユーザー名
//     BASIC_AUTH_PASS … パスワード
// ============================================================

// ブラウザのログイン画面に表示される名前
const REALM = 'Team Schedule';

// 認証で止めたときの応答に付ける共通のヘッダー
const COMMON_HEADERS = {
  'Content-Type': 'text/plain; charset=utf-8',
  'Cache-Control': 'no-store',             // 途中のサーバーやブラウザに保存させない
  'X-Robots-Tag': 'noindex, nofollow',     // 検索エンジンに載せない
};

export async function onRequest(context) {
  const { request, env, next } = context;
  const expectedUser = env.BASIC_AUTH_USER;
  const expectedPass = env.BASIC_AUTH_PASS;

  // 環境変数が設定されていないときは、誰も入れない（設定漏れで丸見えになるのを防ぐ）
  if (!expectedUser || !expectedPass) {
    return new Response('認証の設定が完了していないため、表示できません。', {
      status: 500,
      headers: COMMON_HEADERS,
    });
  }

  const credentials = parseBasicAuth(request.headers.get('Authorization'));
  if (credentials) {
    // ユーザー名とパスワードの両方を必ず比べる（片方だけ比べて終わらせない）
    const [userOk, passOk] = await Promise.all([
      safeEqual(credentials.user, expectedUser),
      safeEqual(credentials.pass, expectedPass),
    ]);
    if (userOk && passOk) {
      return next(); // 正しければ、本来のページを返す
    }
  }

  // 未入力・間違いのときは、ブラウザにログイン画面を出させる
  return new Response('ユーザー名とパスワードが必要です。', {
    status: 401,
    headers: {
      ...COMMON_HEADERS,
      'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
    },
  });
}

// 「Authorization: Basic xxxx」から、ユーザー名とパスワードを取り出す
// 形がおかしいときは null を返す
function parseBasicAuth(header) {
  if (!header) return null;
  const match = header.match(/^Basic\s+([A-Za-z0-9+/=]+)$/i);
  if (!match) return null;
  try {
    // xxxx の部分は「ユーザー名:パスワード」を Base64（文字を英数字に置き換える方式）にしたもの
    const binary = atob(match[1]);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    const decoded = new TextDecoder().decode(bytes); // 日本語のユーザー名にも対応
    const sep = decoded.indexOf(':');
    if (sep < 0) return null;
    return { user: decoded.slice(0, sep), pass: decoded.slice(sep + 1) };
  } catch (e) {
    return null;
  }
}

// 2つの文字列が同じかを、かかる時間から中身を推測されない方法で比べる
// （長さが違っても比べられるよう、先に同じ長さの値 SHA-256 に変換してから比べる）
async function safeEqual(a, b) {
  const encoder = new TextEncoder();
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(hashA, hashB);
}
