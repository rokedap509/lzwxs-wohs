export async function onRequest(context) {
  const { request, env } = context;
  const authHeader = request.headers.get('Authorization');

  // 从环境变量获取凭据，未配置则直接拒绝
  const VALID_USER = env.AUTH_USER;
  const VALID_PASS = env.AUTH_PASS;
  if (!VALID_USER || !VALID_PASS) {
    return new Response('未配置认证凭据', { status: 500 });
  }

  // 无认证头则要求登录
  if (!authHeader) {
    return new Response('请输入账号密码', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="Protected Area"' }
    });
  }

  // 解析并验证凭据
  const [scheme, encoded] = authHeader.split(' ');
  if (scheme !== 'Basic' || !encoded) {
    return new Response('无效认证格式', { status: 400 });
  }

  const decoded = atob(encoded);
  const [user, pass] = decoded.split(':');
  if (user !== VALID_USER || pass !== VALID_PASS) {
    return new Response('账号或密码错误', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="Protected Area"' }
    });
  }

  // 验证通过，继续请求
  return context.next();
}