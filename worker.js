// =====================================================
// نظام سهل - إدارة الصالون المتكامل
// Enhanced Security & Complete Features
// Version: 2.1.0
// =====================================================

// تعليق: يوصى بإضافة الفهارس التالية لقاعدة البيانات لتحسين الأداء:
// CREATE INDEX idx_users_email ON users(email);
// CREATE INDEX idx_customers_name ON customers(full_name);
// CREATE INDEX idx_appointments_date ON appointments(appointment_date);
// CREATE INDEX idx_appointments_status ON appointments(status);
// CREATE INDEX idx_transactions_date ON transactions(date);
// CREATE INDEX idx_services_category ON services(category);
// CREATE INDEX idx_inventory_category ON inventory(category);
// CREATE INDEX idx_appointments_customer ON appointments(customer_id);
// CREATE INDEX idx_appointments_employee ON appointments(employee_id);

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  JWT_SECRET: string;
  R2_BUCKET?: R2Bucket;
  KV?: KVNamespace;
  // إضافة متغيرات بيئية اختيارية للتكوين
  CORS_ORIGINS?: string; // مفصولة بفواصل، مثال: "https://example.com,https://app.example.com"
  RATE_LIMIT_REQUESTS?: string; // الحد الأقصى للطلبات في الدقيقة
  SESSION_DURATION?: string; // مدة الجلسة بالساعات
}

// =====================================================
// 1. Security & Helper Functions - محسّنة
// =====================================================

// إنشاء JWT Token آمن
async function createSecureToken(payload: any, secret: string, env?: Env): Promise<string> {
  // التحقق من وجود سر JWT آمن
  if (!secret || secret === 'sahl-secret-2024') {
    console.error('Warning: Using default JWT secret. Please set a secure JWT_SECRET in environment variables.');
  }
  
  const encoder = new TextEncoder();
  
  // Header
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  
  // Payload with expiration - استخدام قيمة قابلة للتكوين
  const sessionHours = env?.SESSION_DURATION ? parseInt(env.SESSION_DURATION) : 24;
  const data = {
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (sessionHours * 60 * 60)
  };
  
  const encodedPayload = btoa(JSON.stringify(data));
  
  // Create signature
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`${header}.${encodedPayload}`)
  );
  
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
    
  return `${header}.${encodedPayload}.${encodedSignature}`;
}

// التحقق من JWT Token بشكل آمن
async function verifySecureToken(token: string, secret: string): Promise<any> {
  try {
    if (!token) return null;

    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, payload, signature] = parts;

    // Verify signature
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signatureData = Uint8Array.from(
      atob(signature.replace(/-/g, '+').replace(/_/g, '/') + '=='),
      c => c.charCodeAt(0)
    );
    
    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      signatureData,
      encoder.encode(`${header}.${payload}`)
    );
    
    if (!isValid) return null;
    
    // Check expiration
    const data = JSON.parse(atob(payload));
    if (data.exp && data.exp < Math.floor(Date.now() / 1000)) {
      return null; // Token expired
    }
    
    return data;
  } catch (e) {
    console.error('Token verification error:', e);
    return null;
  }
}

// Hash كلمة المرور مع Salt عشوائي آمن
async function hashPassword(password: string, salt?: string): Promise<{ hash: string; salt: string }> {
  const encoder = new TextEncoder();
  
  // استخدام دالة آمنة لتوليد Salt إذا لم يتم توفيره
  const generatedSalt = salt || await generateSecureSalt();
  const data = encoder.encode(password + generatedSalt);
  
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return { hash, salt: generatedSalt };
}

// توليد Salt عشوائي آمن
async function generateSecureSalt(): Promise<string> {
  const buffer = new Uint8Array(16);
  crypto.getRandomValues(buffer);
  return Array.from(buffer)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// التحقق من كلمة المرور
async function verifyPassword(password: string, storedHash: string, salt: string): Promise<boolean> {
  const { hash } = await hashPassword(password, salt);
  return hash === storedHash;
}

// Input Validation - محسّنة
function validateInput(input: any, rules: Record<string, any>): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  for (const [field, rule] of Object.entries(rules)) {
    const value = input[field];
    
    // Required check
    if (rule.required && (value === undefined || value === null || value === '')) {
      errors.push(`${field} مطلوب`);
      continue;
    }
    
    // Skip further validation if field is not required and empty
    if (!rule.required && (value === undefined || value === null || value === '')) {
      continue;
    }
    
    // Type check
    if (rule.type) {
      if (rule.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        errors.push(`${field} يجب أن يكون بريد إلكتروني صالح`);
      }
      if (rule.type === 'number' && (isNaN(Number(value)) || value === '')) {
        errors.push(`${field} يجب أن يكون رقم`);
      }
      if (rule.type === 'date') {
        // تحسين التحقق من التاريخ
        if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
          errors.push(`${field} يجب أن يكون تاريخ صالح (YYYY-MM-DD)`);
        } else {
          const date = new Date(value);
          if (isNaN(date.getTime())) {
            errors.push(`${field} يجب أن يكون تاريخ صالح`);
          }
        }
      }
    }
    
    // Min/Max length
    if (rule.minLength && value.length < rule.minLength) {
      errors.push(`${field} يجب أن يكون ${rule.minLength} أحرف على الأقل`);
    }
    if (rule.maxLength && value.length > rule.maxLength) {
      errors.push(`${field} يجب ألا يتجاوز ${rule.maxLength} حرف`);
    }
    
    // Min/Max value
    if (rule.min !== undefined && Number(value) < rule.min) {
      errors.push(`${field} يجب أن يكون ${rule.min} على الأقل`);
    }
    if (rule.max !== undefined && Number(value) > rule.max) {
      errors.push(`${field} يجب ألا يتجاوز ${rule.max}`);
    }
    
    // Enum
    if (rule.enum && !rule.enum.includes(value)) {
      errors.push(`${field} يجب أن يكون أحد: ${rule.enum.join(', ')}`);
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

// Sanitize input to prevent XSS - محسّنة
function sanitizeInput(input: any): any {
  if (typeof input === 'string') {
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/\//g, '&#x2F;');
  }
  
  if (typeof input === 'object' && input !== null) {
    const sanitized: any = {};
    for (const [key, value] of Object.entries(input)) {
      sanitized[key] = sanitizeInput(value);
    }
    return sanitized;
  }
  
  return input;
}

// Rate Limiting - محسّنة
async function checkRateLimit(request: Request, env: Env): Promise<boolean> {
  if (!env.KV) return true; // Skip if KV not available
  
  const limit = env.RATE_LIMIT_REQUESTS ? parseInt(env.RATE_LIMIT_REQUESTS) : 100;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const key = `rate_limit:${ip}`;
  const current = parseInt(await env.KV.get(key) || '0');
  
  if (current >= limit) {
    return false;
  }
  
  await env.KV.put(key, String(current + 1), { expirationTtl: 60 });
  return true;
}

// CORS Response Helper - محسّنة
function jsonResponse(data: any, status = 200, env?: Env): Response {
  // تحديد المصادر المسموح بها بناءً على متغيرات البيئة
  let allowOrigin = '*';
  if (env?.CORS_ORIGINS) {
    const origins = env.CORS_ORIGINS.split(',');
    const requestOrigin = new URL(new Request('').url).origin;
    if (origins.includes(requestOrigin)) {
      allowOrigin = requestOrigin;
    }
  }
  
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': allowOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
  });
}

// Error Handler مع Logging - محسّنة
function handleError(context: string, error: any, details?: any): Response {
  const errorId = crypto.randomUUID();
  console.error(`[ERROR ${errorId}] ${context}:`, {
    error: error?.message || error,
    stack: error?.stack,
    details,
    timestamp: new Date().toISOString()
  });
  
  // Don't expose internal errors to client
  return jsonResponse({
    success: false,
    error: 'حدث خطأ في النظام',
    errorId,
    context: context
  }, 500);
}

// دالة مساعدة للتحقق من صحة التاريخ
function isValidDate(dateString: string): boolean {
  const regex = /^\d{4}-\d{2}-\d{2}$/;
  if (!regex.test(dateString)) return false;
  
  const date = new Date(dateString);
  return !isNaN(date.getTime());
}

// دالة مساعدة للتحقق من صحة الرقم
function isValidNumber(value: any): boolean {
  return !isNaN(parseFloat(value)) && isFinite(value);
}

// =====================================================
// 2. Authentication Middleware - محسّن
// =====================================================

async function authenticateRequest(request: Request, env: Env): Promise<{ valid: boolean; user?: any }> {
  const url = new URL(request.url);
  
  // Public endpoints
  const publicPaths = [
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/verify',
    '/api/health',
    '/login',
    '/'
  ];
  
  if (publicPaths.includes(url.pathname) || url.pathname.startsWith('/static/')) {
    return { valid: true };
  }
  
  // Check Authorization header
  const authorization = request.headers.get('Authorization');
  if (!authorization || !authorization.startsWith('Bearer ')) {
    return { valid: false };
  }
  
  const token = authorization.substring(7);
  const user = await verifySecureToken(token, env.JWT_SECRET);
  
  if (!user) {
    return { valid: false };
  }
  
  // Verify user still exists and is active - إصلاح المنطق
  try {
    const dbUser = await env.DB.prepare(
      'SELECT id, is_active FROM users WHERE id = ? AND is_active = 1'
    ).bind(user.id).first();
    
    if (!dbUser) {
      return { valid: false };
    }
    
    return { valid: true, user };
  } catch (e) {
    console.error('User verification error:', e);
    return { valid: false }; // رفض الوصول في حالة فشل الاستعلام
  }
}

// =====================================================
// 3. Main Worker with Enhanced Routing
// =====================================================

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    
    // Security Headers
    const securityHeaders = {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:;",
    };
    
    // Handle OPTIONS (CORS preflight)
    if (request.method === 'OPTIONS') {
      // تحديد المصادر المسموح بها بناءً على متغيرات البيئة
      let allowOrigin = '*';
      if (env.CORS_ORIGINS) {
        const origins = env.CORS_ORIGINS.split(',');
        const requestOrigin = request.headers.get('Origin') || '';
        if (origins.includes(requestOrigin)) {
          allowOrigin = requestOrigin;
        }
      }
      
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': allowOrigin,
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400',
        }
      });
    }
    
    // Rate Limiting
    const rateLimitOk = await checkRateLimit(request, env);
    if (!rateLimitOk) {
      return jsonResponse({ 
        success: false, 
        error: 'تم تجاوز حد الطلبات، حاول مرة أخرى لاحقاً' 
      }, 429, env);
    }
    
    // Serve login page
    if (url.pathname === '/login' || url.pathname === '/') {
      return new Response(getLoginPageHTML(), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          ...securityHeaders
        }
      });
    }
    
    // API Routes
    if (url.pathname.startsWith('/api/')) {
      try {
        // Authentication check
        const auth = await authenticateRequest(request, env);
        
        // Public endpoints
        if (url.pathname === '/api/health') {
          return jsonResponse({
            success: true,
            status: 'healthy',
            system: 'سهل - نظام إدارة الصالون',
            version: '2.1.0',
            timestamp: new Date().toISOString()
          }, 200, env);
        }
        
        if (url.pathname === '/api/auth/login') {
          return await handleLogin(request, env);
        }
        
        if (url.pathname === '/api/auth/register') {
          return await handleRegister(request, env);
        }
        
        if (url.pathname === '/api/auth/verify') {
          return await handleVerifyToken(request, env);
        }
        
        // Protected endpoints
        if (!auth.valid) {
          return jsonResponse({ 
            success: false, 
            error: 'غير مصرح لك بالدخول',
            code: 'UNAUTHORIZED'
          }, 401, env);
        }
        
        // Customer routes
        if (url.pathname === '/api/customers') {
          return await handleCustomers(request, env, auth.user);
        }
        if (url.pathname.match(/^\/api\/customers\/\d+$/)) {
          const id = url.pathname.split('/')[3];
          return await handleCustomerById(request, env, auth.user, id);
        }
        
        // Appointment routes
        if (url.pathname === '/api/appointments') {
          return await handleAppointments(request, env, auth.user);
        }
        if (url.pathname.match(/^\/api\/appointments\/\d+$/)) {
          const id = url.pathname.split('/')[3];
          return await handleAppointmentById(request, env, auth.user, id);
        }
        
        // Transaction routes
        if (url.pathname === '/api/transactions') {
          return await handleTransactions(request, env, auth.user);
        }
        if (url.pathname.match(/^\/api\/transactions\/\d+$/)) {
          const id = url.pathname.split('/')[3];
          return await handleTransactionById(request, env, auth.user, id);
        }
        
        // Service routes
        if (url.pathname === '/api/services') {
          return await handleServices(request, env, auth.user);
        }
        if (url.pathname.match(/^\/api\/services\/\d+$/)) {
          const id = url.pathname.split('/')[3];
          return await handleServiceById(request, env, auth.user, id);
        }
        
        // Inventory routes
        if (url.pathname === '/api/inventory') {
          return await handleInventory(request, env, auth.user);
        }
        if (url.pathname.match(/^\/api\/inventory\/\d+$/)) {
          const id = url.pathname.split('/')[3];
          return await handleInventoryById(request, env, auth.user, id);
        }
        
        // Upload routes
        if (url.pathname === '/api/upload/avatar') {
          return await handleAvatarUpload(request, env, auth.user);
        }
        if (url.pathname === '/api/upload/receipt') {
          return await handleReceiptUpload(request, env, auth.user);
        }
        
        // Additional routes
        if (url.pathname === '/api/users') {
          return await handleUsers(request, env, auth.user);
        }
        if (url.pathname === '/api/dashboard') {
          return await handleDashboard(request, env, auth.user);
        }
        if (url.pathname === '/api/reports') {
          return await handleReports(request, env, auth.user);
        }
        
        return jsonResponse({ 
          success: false, 
          error: 'المسار غير موجود',
          path: url.pathname 
        }, 404, env);
        
      } catch (error) {
        return handleError('API Route', error, { path: url.pathname });
      }
    }
    
    // Serve static assets
    try {
      return await env.ASSETS.fetch(request);
    } catch (e) {
      try {
        // Try index.html for SPA routing
        return await env.ASSETS.fetch(new Request(new URL('/', url), request));
      } catch (e2) {
        return new Response('Not found', { status: 404 });
      }
    }
  }
};

// =====================================================
// 4. Authentication Handlers - محسّنة بالكامل
// =====================================================

async function handleLogin(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') {
    return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
  }
  
  try {
    const body = await request.json();
    
    // Input validation
    const validation = validateInput(body, {
      email: { required: true, type: 'email' },
      password: { required: true, minLength: 6 }
    });
    
    if (!validation.valid) {
      return jsonResponse({
        success: false,
        errors: validation.errors
      }, 400, env);
    }
    
    // Try to find user
    const user = await env.DB.prepare(`
      SELECT id, full_name, email, role, password_hash, password_salt, is_active 
      FROM users 
      WHERE email = ? AND is_active = 1
    `).bind(body.email).first();
    
    if (user) {
      // Verify password
      const isValid = await verifyPassword(
        body.password,
        user.password_hash,
        user.password_salt
      );
      
      if (isValid) {
        const token = await createSecureToken({
          id: user.id,
          email: user.email,
          name: user.full_name,
          role: user.role
        }, env.JWT_SECRET, env);
        
        return jsonResponse({
          success: true,
          token,
          user: {
            id: user.id,
            name: user.full_name,
            email: user.email,
            role: user.role
          },
          message: 'تم تسجيل الدخول بنجاح'
        }, 200, env);
      }
    }
    
    // Check default admin account
    if (body.email === 'admin@sahl.com' && body.password === 'admin123') {
      // Create admin if not exists
      try {
        const { hash, salt } = await hashPassword('admin123');
        
        await env.DB.prepare(`
          INSERT OR IGNORE INTO users 
          (full_name, email, password_hash, password_salt, role, is_active)
          VALUES ('مدير النظام', 'admin@sahl.com', ?, ?, 'admin', 1)
        `).bind(hash, salt).run();
        
        const token = await createSecureToken({
          id: 1,
          email: 'admin@sahl.com',
          name: 'مدير النظام',
          role: 'admin'
        }, env.JWT_SECRET, env);
        
        return jsonResponse({
          success: true,
          token,
          user: {
            id: 1,
            name: 'مدير النظام',
            email: 'admin@sahl.com',
            role: 'admin'
          },
          message: 'تم تسجيل الدخول بنجاح'
        }, 200, env);
      } catch (e) {
        console.error('Admin creation error:', e);
      }
    }
    
    return jsonResponse({
      success: false,
      error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
    }, 401, env);
    
  } catch (error) {
    return handleError('Login', error);
  }
}

async function handleRegister(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') {
    return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
  }
  
  try {
    const body = await request.json();
    
    // Input validation
    const validation = validateInput(body, {
      full_name: { required: true, minLength: 2, maxLength: 100 },
      email: { required: true, type: 'email' },
      password: { required: true, minLength: 6, maxLength: 50 },
      phone: { required: false, minLength: 10, maxLength: 20 }
    });
    
    if (!validation.valid) {
      return jsonResponse({
        success: false,
        errors: validation.errors
      }, 400, env);
    }
    
    // Sanitize input
    const sanitized = sanitizeInput(body);
    
    // Hash password
    const { hash, salt } = await hashPassword(sanitized.password);
    
    // Create user
    const result = await env.DB.prepare(`
      INSERT INTO users 
      (full_name, email, password_hash, password_salt, phone, role, is_active, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
    `).bind(
      sanitized.full_name,
      sanitized.email,
      hash,
      salt,
      sanitized.phone || null,
      sanitized.role || 'employee'
    ).run();
    
    if (result.success) {
      const token = await createSecureToken({
        id: result.meta?.last_row_id,
        email: sanitized.email,
        name: sanitized.full_name,
        role: sanitized.role || 'employee'
      }, env.JWT_SECRET, env);
      
      return jsonResponse({
        success: true,
        token,
        user: {
          id: result.meta?.last_row_id,
          name: sanitized.full_name,
          email: sanitized.email,
          role: sanitized.role || 'employee'
        },
        message: 'تم إنشاء الحساب بنجاح'
      }, 201, env);
    }
    
    return jsonResponse({ success: false, error: 'فشل في إنشاء الحساب' }, 400, env);
    
  } catch (error: any) {
    if (error.message?.includes('UNIQUE')) {
      return jsonResponse({
        success: false,
        error: 'البريد الإلكتروني مستخدم بالفعل'
      }, 400, env);
    }
    
    return handleError('Register', error);
  }
}

async function handleVerifyToken(request: Request, env: Env): Promise<Response> {
  const authorization = request.headers.get('Authorization');
  
  if (!authorization || !authorization.startsWith('Bearer ')) {
    return jsonResponse({ valid: false }, 401, env);
  }
  
  const token = authorization.substring(7);
  const user = await verifySecureToken(token, env.JWT_SECRET);
  
  if (user) {
    return jsonResponse({
      valid: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    }, 200, env);
  }
  
  return jsonResponse({ valid: false }, 401, env);
}

// =====================================================
// 5. Upload Handlers - محسّنة
// =====================================================

async function handleAvatarUpload(request: Request, env: Env, user: any): Promise<Response> {
  if (request.method !== 'POST') {
    return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
  }
  
  try {
    const formData = await request.formData();
    const file = formData.get('avatar') as File;
    
    if (!file) {
      return jsonResponse({ 
        success: false, 
        error: 'لم يتم تحديد ملف' 
      }, 400, env);
    }
    
    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowedTypes.includes(file.type)) {
      return jsonResponse({ 
        success: false, 
        error: 'نوع الملف غير مسموح' 
      }, 400, env);
    }
    
    // Validate file size (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
      return jsonResponse({ 
        success: false, 
        error: 'حجم الملف كبير جداً (الحد الأقصى 5MB)' 
      }, 400, env);
    }
    
    // Generate unique filename
    const extension = file.name.split('.').pop();
    const filename = `avatar-${user.id}-${Date.now()}.${extension}`;
    
    // Store in R2 if available
    if (env.R2_BUCKET) {
      await env.R2_BUCKET.put(filename, file.stream(), {
        httpMetadata: {
          contentType: file.type,
        },
        customMetadata: {
          uploadedBy: String(user.id),
          uploadedAt: new Date().toISOString()
        }
      });
      
      // Update user avatar in database
      await env.DB.prepare(`
        UPDATE users SET avatar_url = ? WHERE id = ?
      `).bind(`/files/${filename}`, user.id).run();
      
      return jsonResponse({
        success: true,
        url: `/files/${filename}`,
        message: 'تم رفع الصورة بنجاح'
      }, 200, env);
    }
    
    // Fallback to KV storage for small files
    if (env.KV && file.size < 1024 * 1024) { // Max 1MB for KV
      const arrayBuffer = await file.arrayBuffer();
      const base64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
      
      await env.KV.put(`avatar:${user.id}`, base64, {
        metadata: {
          contentType: file.type,
          filename: filename
        }
      });
      
      return jsonResponse({
        success: true,
        url: `data:${file.type};base64,${base64}`,
        message: 'تم رفع الصورة بنجاح'
      }, 200, env);
    }
    
    return jsonResponse({ 
      success: false, 
      error: 'خدمة التخزين غير متاحة' 
    }, 503, env);
    
  } catch (error) {
    return handleError('Avatar Upload', error);
  }
}

async function handleReceiptUpload(request: Request, env: Env, user: any): Promise<Response> {
  if (request.method !== 'POST') {
    return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
  }
  
  try {
    const formData = await request.formData();
    const file = formData.get('receipt') as File;
    const transactionId = formData.get('transaction_id') as string;
    
    if (!file) {
      return jsonResponse({ 
        success: false, 
        error: 'لم يتم تحديد ملف' 
      }, 400, env);
    }
    
    if (!transactionId) {
      return jsonResponse({ 
        success: false, 
        error: 'معرف المعاملة مطلوب' 
      }, 400, env);
    }
    
    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
    if (!allowedTypes.includes(file.type)) {
      return jsonResponse({ 
        success: false, 
        error: 'نوع الملف غير مسموح (JPG, PNG, PDF فقط)' 
      }, 400, env);
    }
    
    // Validate file size (max 10MB)
    if (file.size > 10 * 1024 * 1024) {
      return jsonResponse({ 
        success: false, 
        error: 'حجم الملف كبير جداً (الحد الأقصى 10MB)' 
      }, 400, env);
    }
    
    // Generate unique filename
    const extension = file.name.split('.').pop();
    const filename = `receipt-${transactionId}-${Date.now()}.${extension}`;
    
    // Store in R2 if available
    if (env.R2_BUCKET) {
      await env.R2_BUCKET.put(filename, file.stream(), {
        httpMetadata: {
          contentType: file.type,
        },
        customMetadata: {
          transactionId: transactionId,
          uploadedBy: String(user.id),
          uploadedAt: new Date().toISOString()
        }
      });
      
      // Update transaction with receipt URL
      await env.DB.prepare(`
        UPDATE transactions 
        SET receipt_url = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
      `).bind(`/files/${filename}`, transactionId).run();
      
      return jsonResponse({
        success: true,
        url: `/files/${filename}`,
        message: 'تم رفع الإيصال بنجاح'
      }, 200, env);
    }
    
    return jsonResponse({ 
      success: false, 
      error: 'خدمة التخزين غير متاحة' 
    }, 503, env);
    
  } catch (error) {
    return handleError('Receipt Upload', error);
  }
}

// =====================================================
// 6. Customers Handlers - محسّنة بالكامل
// =====================================================

async function handleCustomers(request: Request, env: Env, user: any): Promise<Response> {
  const { searchParams } = new URL(request.url);
  
  if (request.method === 'GET') {
    try {
      const search = searchParams.get('search');
      const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100);
      const offset = parseInt(searchParams.get('offset') || '0');
      
      let query;
      let params = [];
      
      if (search) {
        const sanitizedSearch = sanitizeInput(search);
        query = `
          SELECT * FROM customers
          WHERE is_active = 1
          AND (full_name LIKE ? OR phone LIKE ? OR email LIKE ?)
          ORDER BY created_at DESC
          LIMIT ?
        `;
        params = [`%${sanitizedSearch}%`, `%${sanitizedSearch}%`, `%${sanitizedSearch}%`, limit];
      } else {
        query = `
          SELECT * FROM customers
          WHERE is_active = 1
          ORDER BY created_at DESC
          LIMIT ? OFFSET ?
        `;
        params = [limit, offset];
      }
      
      const result = await env.DB.prepare(query).bind(...params).all();
      
      // Get total count for pagination
      const countResult = await env.DB.prepare(
        'SELECT COUNT(*) as total FROM customers WHERE is_active = 1'
      ).first();
      
      return jsonResponse({
        success: true,
        results: result.results || [],
        count: result.results?.length || 0,
        total: countResult?.total || 0,
        pagination: { limit, offset }
      }, 200, env);
      
    } catch (error) {
      return handleError('Get Customers', error);
    }
  }
  
  if (request.method === 'POST') {
    try {
      const body = await request.json();
      
      const validation = validateInput(body, {
        full_name: { required: true, minLength: 2, maxLength: 100 },
        phone: { required: false, minLength: 10, maxLength: 20 },
        email: { required: false, type: 'email' },
        notes: { required: false, maxLength: 500 }
      });
      
      if (!validation.valid) {
        return jsonResponse({
          success: false,
          errors: validation.errors
        }, 400, env);
      }
      
      const sanitized = sanitizeInput(body);
      
      const result = await env.DB.prepare(`
        INSERT INTO customers (full_name, phone, email, notes, is_active, created_at, created_by)
        VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, ?)
      `).bind(
        sanitized.full_name,
        sanitized.phone || null,
        sanitized.email || null,
        sanitized.notes || null,
        user.id
      ).run();
      
      if (result.success) {
        return jsonResponse({
          success: true,
          id: result.meta?.last_row_id,
          message: 'تم إضافة العميل بنجاح'
        }, 201, env);
      }
      
      return jsonResponse({ success: false, error: 'فشل في إضافة العميل' }, 400, env);
      
    } catch (error) {
      return handleError('Create Customer', error);
    }
  }
  
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
}

async function handleCustomerById(request: Request, env: Env, user: any, id: string): Promise<Response> {
  if (request.method === 'GET') {
    try {
      // تحسين استعلام العميل ليشمل إحصائيات المواعيد والإيرادات
      const customer = await env.DB.prepare(`
        SELECT 
          c.*,
          COUNT(DISTINCT a.id) as appointment_count,
          SUM(CASE WHEN a.status = 'completed' THEN a.price ELSE 0 END) as total_spent
        FROM customers c
        LEFT JOIN appointments a ON c.id = a.customer_id
        WHERE c.id = ? AND c.is_active = 1
        GROUP BY c.id
      `).bind(id).first();
      
      if (!customer) {
        return jsonResponse({ success: false, error: 'العميل غير موجود' }, 404, env);
      }
      
      return jsonResponse({ success: true, data: customer }, 200, env);
      
    } catch (error) {
      return handleError('Get Customer', error);
    }
  }
  
  if (request.method === 'PUT') {
    try {
      const body = await request.json();
      
      const validation = validateInput(body, {
        full_name: { required: false, minLength: 2, maxLength: 100 },
        phone: { required: false, minLength: 10, maxLength: 20 },
        email: { required: false, type: 'email' },
        notes: { required: false, maxLength: 500 }
      });
      
      if (!validation.valid) {
        return jsonResponse({
          success: false,
          errors: validation.errors
        }, 400, env);
      }
      
      const sanitized = sanitizeInput(body);
      
      const result = await env.DB.prepare(`
        UPDATE customers 
        SET full_name = COALESCE(?, full_name),
            phone = COALESCE(?, phone),
            email = COALESCE(?, email),
            notes = COALESCE(?, notes),
            updated_at = CURRENT_TIMESTAMP,
            updated_by = ?
        WHERE id = ? AND is_active = 1
      `).bind(
        sanitized.full_name,
        sanitized.phone,
        sanitized.email,
        sanitized.notes,
        user.id,
        id
      ).run();
      
      if (result.success && result.meta?.changes > 0) {
        return jsonResponse({ success: true, message: 'تم تحديث بيانات العميل' }, 200, env);
      }
      
      return jsonResponse({ success: false, error: 'العميل غير موجود' }, 404, env);
      
    } catch (error) {
      return handleError('Update Customer', error);
    }
  }
  
  if (request.method === 'DELETE') {
    try {
      const result = await env.DB.prepare(`
        UPDATE customers 
        SET is_active = 0, 
            updated_at = CURRENT_TIMESTAMP, 
            deleted_by = ?, 
            deleted_at = CURRENT_TIMESTAMP 
        WHERE id = ?
      `).bind(user.id, id).run();
      
      if (result.success && result.meta?.changes > 0) {
        return jsonResponse({ success: true, message: 'تم حذف العميل' }, 200, env);
      }
      
      return jsonResponse({ success: false, error: 'العميل غير موجود' }, 404, env);
      
    } catch (error) {
      return handleError('Delete Customer', error);
    }
  }
  
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
}

// =====================================================
// 7. Appointments Handlers - محسّنة
// =====================================================

async function handleAppointments(request: Request, env: Env, user: any): Promise<Response> {
  const { searchParams } = new URL(request.url);
  
  if (request.method === 'GET') {
    try {
      const startDate = searchParams.get('start_date');
      const endDate = searchParams.get('end_date');
      
      let start = startDate || new Date().toISOString().split('T')[0];
      let end = endDate || start;
      
      // التحقق من صحة التواريخ
      if (!isValidDate(start) || !isValidDate(end)) {
        return jsonResponse({
          success: false,
          error: 'تواريخ غير صالحة'
        }, 400, env);
      }
      
      const result = await env.DB.prepare(`
        SELECT 
          a.*,
          c.full_name as customer_name,
          c.phone as customer_phone,
          s.name as service_name,
          s.duration_minutes,
          s.price as service_price,
          u.full_name as employee_name
        FROM appointments a
        LEFT JOIN customers c ON a.customer_id = c.id
        LEFT JOIN services s ON a.service_id = s.id
        LEFT JOIN users u ON a.employee_id = u.id
        WHERE date(a.appointment_date) BETWEEN ? AND ?
        ORDER BY a.appointment_date, a.id
      `).bind(start, end).all();
      
      return jsonResponse({
        success: true,
        results: result.results || [],
        period: { start, end }
      }, 200, env);
      
    } catch (error) {
      return handleError('Get Appointments', error);
    }
  }
  
  if (request.method === 'POST') {
    try {
      const body = await request.json();
      
      const validation = validateInput(body, {
        customer_id: { required: true, type: 'number' },
        service_id: { required: true, type: 'number' },
        appointment_date: { required: true, type: 'date' },
        employee_id: { required: false, type: 'number' },
        status: { required: false, enum: ['scheduled', 'confirmed', 'completed', 'cancelled'] },
        notes: { required: false, maxLength: 500 },
        price: { required: false, type: 'number', min: 0 }
      });
      
      if (!validation.valid) {
        return jsonResponse({
          success: false,
          errors: validation.errors
        }, 400, env);
      }
      
      // التحقق من صحة التاريخ
      if (!isValidDate(body.appointment_date)) {
        return jsonResponse({
          success: false,
          error: 'تاريخ الموعد غير صالح'
        }, 400, env);
      }
      
      // Check for conflicts - تحسين التحقق من التعارضات
      if (body.employee_id) {
        const conflict = await env.DB.prepare(`
          SELECT id FROM appointments
          WHERE employee_id = ? 
          AND appointment_date = ?
          AND status IN ('scheduled', 'confirmed')
          AND id != ?
        `).bind(body.employee_id, body.appointment_date, body.id || 0).first();
        
        if (conflict) {
          return jsonResponse({
            success: false,
            error: 'الموظف لديه موعد آخر في نفس الوقت'
          }, 400, env);
        }
      }
      
      const result = await env.DB.prepare(`
        INSERT INTO appointments 
        (customer_id, service_id, employee_id, appointment_date, status, notes, price, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).bind(
        body.customer_id,
        body.service_id,
        body.employee_id || null,
        body.appointment_date,
        body.status || 'scheduled',
        body.notes || null,
        body.price ? parseFloat(body.price) : null,
        user.id
      ).run();
      
      if (result.success) {
        return jsonResponse({
          success: true,
          id: result.meta?.last_row_id,
          message: 'تم حجز الموعد بنجاح'
        }, 201, env);
      }
      
      return jsonResponse({ success: false, error: 'فشل في حجز الموعد' }, 400, env);
      
    } catch (error) {
      return handleError('Create Appointment', error);
    }
  }
  
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
}

async function handleAppointmentById(request: Request, env: Env, user: any, id: string): Promise<Response> {
  if (request.method === 'GET') {
    try {
      const appointment = await env.DB.prepare(`
        SELECT 
          a.*,
          c.full_name as customer_name,
          c.phone as customer_phone,
          c.email as customer_email,
          s.name as service_name,
          s.duration_minutes,
          s.price as service_price,
          u.full_name as employee_name
        FROM appointments a
        LEFT JOIN customers c ON a.customer_id = c.id
        LEFT JOIN services s ON a.service_id = s.id
        LEFT JOIN users u ON a.employee_id = u.id
        WHERE a.id = ?
      `).bind(id).first();
      
      if (!appointment) {
        return jsonResponse({ success: false, error: 'الموعد غير موجود' }, 404, env);
      }
      
      return jsonResponse({ success: true, data: appointment }, 200, env);
      
    } catch (error) {
      return handleError('Get Appointment', error);
    }
  }
  
  if (request.method === 'PUT') {
    try {
      const body = await request.json();
      
      const validation = validateInput(body, {
        status: { required: false, enum: ['scheduled', 'confirmed', 'completed', 'cancelled'] },
        appointment_date: { required: false, type: 'date' },
        employee_id: { required: false, type: 'number' },
        notes: { required: false, maxLength: 500 },
        price: { required: false, type: 'number', min: 0 }
      });
      
      if (!validation.valid) {
        return jsonResponse({
          success: false,
          errors: validation.errors
        }, 400, env);
      }
      
      // التحقق من صحة التاريخ إذا تم توفيره
      if (body.appointment_date && !isValidDate(body.appointment_date)) {
        return jsonResponse({
          success: false,
          error: 'تاريخ الموعد غير صالح'
        }, 400, env);
      }
      
      // Check for conflicts if changing date or employee
      if (body.appointment_date || body.employee_id) {
        const currentAppointment = await env.DB.prepare(`
          SELECT appointment_date, employee_id FROM appointments WHERE id = ?
        `).bind(id).first();
        
        if (currentAppointment) {
          const newDate = body.appointment_date || currentAppointment.appointment_date;
          const newEmployeeId = body.employee_id !== undefined ? body.employee_id : currentAppointment.employee_id;
          
          if (newEmployeeId) {
            const conflict = await env.DB.prepare(`
              SELECT id FROM appointments
              WHERE employee_id = ? 
              AND appointment_date = ?
              AND status IN ('scheduled', 'confirmed')
              AND id != ?
            `).bind(newEmployeeId, newDate, id).first();
            
            if (conflict) {
              return jsonResponse({
                success: false,
                error: 'الموظف لديه موعد آخر في نفس الوقت'
              }, 400, env);
            }
          }
        }
      }
      
      const result = await env.DB.prepare(`
        UPDATE appointments 
        SET status = COALESCE(?, status),
            appointment_date = COALESCE(?, appointment_date),
            employee_id = COALESCE(?, employee_id),
            notes = COALESCE(?, notes),
            price = COALESCE(?, price),
            updated_at = CURRENT_TIMESTAMP,
            updated_by = ?
        WHERE id = ?
      `).bind(
        body.status,
        body.appointment_date,
        body.employee_id,
        body.notes,
        body.price ? parseFloat(body.price) : null,
        user.id,
        id
      ).run();
      
      if (result.success && result.meta?.changes > 0) {
        // If completed, create transaction automatically - إصلاح المنطق
        if (body.status === 'completed' && body.price) {
          // التحقق من عدم وجود معاملة بالفعل
          const existingTransaction = await env.DB.prepare(`
            SELECT id FROM transactions WHERE appointment_id = ?
          `).bind(id).first();
          
          if (!existingTransaction) {
            await env.DB.prepare(`
              INSERT INTO transactions (type, category, amount, description, date, appointment_id, created_by)
              VALUES ('income', 'خدمة', ?, 'دفعة موعد رقم ' || ?, date('now'), ?, ?)
            `).bind(body.price, id, id, user.id).run();
          }
        }
        
        return jsonResponse({ success: true, message: 'تم تحديث الموعد' }, 200, env);
      }
      
      return jsonResponse({ success: false, error: 'الموعد غير موجود' }, 404, env);
      
    } catch (error) {
      return handleError('Update Appointment', error);
    }
  }
  
  if (request.method === 'DELETE') {
    try {
      const result = await env.DB.prepare(`
        UPDATE appointments 
        SET status = 'cancelled', 
            updated_at = CURRENT_TIMESTAMP, 
            cancelled_by = ?, 
            cancelled_at = CURRENT_TIMESTAMP 
        WHERE id = ?
      `).bind(user.id, id).run();
      
      if (result.success && result.meta?.changes > 0) {
        return jsonResponse({ success: true, message: 'تم إلغاء الموعد' }, 200, env);
      }
      
      return jsonResponse({ success: false, error: 'الموعد غير موجود' }, 404, env);
      
    } catch (error) {
      return handleError('Cancel Appointment', error);
    }
  }
  
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
}

// =====================================================
// 8. Transactions Handlers - محسّنة
// =====================================================

async function handleTransactions(request: Request, env: Env, user: any): Promise<Response> {
  const { searchParams } = new URL(request.url);
  
  if (request.method === 'GET') {
    try {
      const startDate = searchParams.get('start_date');
      const endDate = searchParams.get('end_date');
      const type = searchParams.get('type');
      
      let start = startDate;
      let end = endDate;
      
      if (!start || !end) {
        const now = new Date();
        start = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
        end = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().split('T')[0];
      }
      
      // التحقق من صحة التواريخ
      if (!isValidDate(start) || !isValidDate(end)) {
        return jsonResponse({
          success: false,
          error: 'تواريخ غير صالحة'
        }, 400, env);
      }
      
      if (type === 'summary') {
        const result = await env.DB.prepare(`
          SELECT 
            type,
            category,
            COUNT(*) as count,
            SUM(amount) as total,
            AVG(amount) as average
          FROM transactions
          WHERE date BETWEEN ? AND ?
          GROUP BY type, category
          ORDER BY type, total DESC
        `).bind(start, end).all();
        
        const totals = await env.DB.prepare(`
          SELECT 
            SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as total_income,
            SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as total_expense,
            SUM(CASE WHEN type = 'income' THEN amount ELSE -amount END) as net_profit
          FROM transactions
          WHERE date BETWEEN ? AND ?
        `).bind(start, end).first();
        
        return jsonResponse({
          success: true,
          results: result.results || [],
          totals,
          period: { start, end }
        }, 200, env);
      }
      
      const result = await env.DB.prepare(`
        SELECT t.*, u.full_name as created_by_name
        FROM transactions t
        LEFT JOIN users u ON t.created_by = u.id
        WHERE t.date BETWEEN ? AND ?
        ORDER BY t.date DESC, t.id DESC
        LIMIT 100
      `).bind(start, end).all();
      
      return jsonResponse({
        success: true,
        results: result.results || [],
        count: result.results?.length || 0,
        period: { start, end }
      }, 200, env);
      
    } catch (error) {
      return handleError('Get Transactions', error);
    }
  }
  
  if (request.method === 'POST') {
    try {
      const body = await request.json();
      
      const validation = validateInput(body, {
        type: { required: true, enum: ['income', 'expense'] },
        category: { required: true, minLength: 2, maxLength: 50 },
        amount: { required: true, type: 'number', min: 0.01 },
        date: { required: true, type: 'date' },
        description: { required: false, maxLength: 500 },
        appointment_id: { required: false, type: 'number' }
      });
      
      if (!validation.valid) {
        return jsonResponse({
          success: false,
          errors: validation.errors
        }, 400, env);
      }
      
      // التحقق من صحة التاريخ
      if (!isValidDate(body.date)) {
        return jsonResponse({
          success: false,
          error: 'التاريخ غير صالح'
        }, 400, env);
      }
      
      // التحقق من صحة المبلغ
      if (!isValidNumber(body.amount)) {
        return jsonResponse({
          success: false,
          error: 'المبلغ غير صالح'
        }, 400, env);
      }
      
      const sanitized = sanitizeInput(body);
      
      const result = await env.DB.prepare(`
        INSERT INTO transactions 
        (type, category, amount, description, date, appointment_id, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).bind(
        sanitized.type,
        sanitized.category,
        parseFloat(sanitized.amount),
        sanitized.description || null,
        sanitized.date,
        sanitized.appointment_id || null,
        user.id
      ).run();
      
      if (result.success) {
        return jsonResponse({
          success: true,
          id: result.meta?.last_row_id,
          message: 'تم إضافة المعاملة بنجاح'
        }, 201, env);
      }
      
      return jsonResponse({ success: false, error: 'فشل في إضافة المعاملة' }, 400, env);
      
    } catch (error) {
      return handleError('Create Transaction', error);
    }
  }
  
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
}

async function handleTransactionById(request: Request, env: Env, user: any, id: string): Promise<Response> {
  if (request.method === 'GET') {
    try {
      const transaction = await env.DB.prepare(`
        SELECT t.*, u.full_name as created_by_name 
        FROM transactions t
        LEFT JOIN users u ON t.created_by = u.id
        WHERE t.id = ?
      `).bind(id).first();
      
      if (!transaction) {
        return jsonResponse({ success: false, error: 'المعاملة غير موجودة' }, 404, env);
      }
      
      return jsonResponse({ success: true, data: transaction }, 200, env);
      
    } catch (error) {
      return handleError('Get Transaction', error);
    }
  }
  
  if (request.method === 'PUT') {
    try {
      const body = await request.json();
      
      const validation = validateInput(body, {
        type: { required: false, enum: ['income', 'expense'] },
        category: { required: false, minLength: 2, maxLength: 50 },
        amount: { required: false, type: 'number', min: 0.01 },
        description: { required: false, maxLength: 500 },
        date: { required: false, type: 'date' }
      });
      
      if (!validation.valid) {
        return jsonResponse({
          success: false,
          errors: validation.errors
        }, 400, env);
      }
      
      // التحقق من صحة التاريخ إذا تم توفيره
      if (body.date && !isValidDate(body.date)) {
        return jsonResponse({
          success: false,
          error: 'التاريخ غير صالح'
        }, 400, env);
      }
      
      // التحقق من صحة المبلغ إذا تم توفيره
      if (body.amount !== undefined && !isValidNumber(body.amount)) {
        return jsonResponse({
          success: false,
          error: 'المبلغ غير صالح'
        }, 400, env);
      }
      
      const result = await env.DB.prepare(`
        UPDATE transactions 
        SET type = COALESCE(?, type),
            category = COALESCE(?, category),
            amount = COALESCE(?, amount),
            description = COALESCE(?, description),
            date = COALESCE(?, date),
            updated_at = CURRENT_TIMESTAMP,
            updated_by = ?
        WHERE id = ?
      `).bind(
        body.type,
        body.category,
        body.amount ? parseFloat(body.amount) : null,
        body.description,
        body.date,
        user.id,
        id
      ).run();
      
      if (result.success && result.meta?.changes > 0) {
        return jsonResponse({ success: true, message: 'تم تحديث المعاملة' }, 200, env);
      }
      
      return jsonResponse({ success: false, error: 'المعاملة غير موجودة' }, 404, env);
      
    } catch (error) {
      return handleError('Update Transaction', error);
    }
  }
  
  if (request.method === 'DELETE') {
    try {
      const result = await env.DB.prepare(`DELETE FROM transactions WHERE id = ?`).bind(id).run();
      
      if (result.success && result.meta?.changes > 0) {
        return jsonResponse({ success: true, message: 'تم حذف المعاملة' }, 200, env);
      }
      
      return jsonResponse({ success: false, error: 'المعاملة غير موجودة' }, 404, env);
      
    } catch (error) {
      return handleError('Delete Transaction', error);
    }
  }
  
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
}

// =====================================================
// 9. Services Handlers - محسّنة
// =====================================================

async function handleServices(request: Request, env: Env, user: any): Promise<Response> {
  if (request.method === 'GET') {
    try {
      const result = await env.DB.prepare(`
        SELECT * FROM services 
        WHERE is_active = 1 
        ORDER BY category, name
      `).all();
      
      return jsonResponse({
        success: true,
        results: result.results || []
      }, 200, env);
      
    } catch (error) {
      return handleError('Get Services', error);
    }
  }
  
  if (request.method === 'POST') {
    try {
      const body = await request.json();
      
      const validation = validateInput(body, {
        name: { required: true, minLength: 2, maxLength: 100 },
        price: { required: true, type: 'number', min: 0 },
        duration_minutes: { required: true, type: 'number', min: 5, max: 480 },
        category: { required: false, maxLength: 50 },
        description: { required: false, maxLength: 500 }
      });
      
      if (!validation.valid) {
        return jsonResponse({
          success: false,
          errors: validation.errors
        }, 400, env);
      }
      
      // التحقق من صحة السعر والمدة
      if (!isValidNumber(body.price) || !isValidNumber(body.duration_minutes)) {
        return jsonResponse({
          success: false,
          error: 'السعر أو المدة غير صالح'
        }, 400, env);
      }
      
      const sanitized = sanitizeInput(body);
      
      const result = await env.DB.prepare(`
        INSERT INTO services 
        (name, description, price, duration_minutes, category, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
      `).bind(
        sanitized.name,
        sanitized.description || null,
        parseFloat(sanitized.price),
        parseInt(sanitized.duration_minutes),
        sanitized.category || null
      ).run();
      
      if (result.success) {
        return jsonResponse({
          success: true,
          id: result.meta?.last_row_id,
          message: 'تم إضافة الخدمة بنجاح'
        }, 201, env);
      }
      
      return jsonResponse({ success: false, error: 'فشل في إضافة الخدمة' }, 400, env);
      
    } catch (error) {
      return handleError('Create Service', error);
    }
  }
  
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
}

async function handleServiceById(request: Request, env: Env, user: any, id: string): Promise<Response> {
  if (request.method === 'GET') {
    try {
      const service = await env.DB.prepare(`
        SELECT 
          s.*,
          COUNT(DISTINCT a.id) as appointment_count,
          SUM(CASE WHEN a.status = 'completed' THEN a.price ELSE 0 END) as total_revenue
        FROM services s
        LEFT JOIN appointments a ON s.id = a.service_id
        WHERE s.id = ? AND s.is_active = 1
        GROUP BY s.id
      `).bind(id).first();
      
      if (!service) {
        return jsonResponse({ success: false, error: 'الخدمة غير موجودة' }, 404, env);
      }
      
      return jsonResponse({ success: true, data: service }, 200, env);
      
    } catch (error) {
      return handleError('Get Service', error);
    }
  }
  
  if (request.method === 'PUT') {
    try {
      const body = await request.json();
      
      const validation = validateInput(body, {
        name: { required: false, minLength: 2, maxLength: 100 },
        price: { required: false, type: 'number', min: 0 },
        duration_minutes: { required: false, type: 'number', min: 5, max: 480 },
        category: { required: false, maxLength: 50 },
        description: { required: false, maxLength: 500 }
      });
      
      if (!validation.valid) {
        return jsonResponse({
          success: false,
          errors: validation.errors
        }, 400, env);
      }
      
      // التحقق من صحة السعر والمدة إذا تم توفيرهما
      if (body.price !== undefined && !isValidNumber(body.price)) {
        return jsonResponse({
          success: false,
          error: 'السعر غير صالح'
        }, 400, env);
      }
      
      if (body.duration_minutes !== undefined && !isValidNumber(body.duration_minutes)) {
        return jsonResponse({
          success: false,
          error: 'المدة غير صالحة'
        }, 400, env);
      }
      
      const result = await env.DB.prepare(`
        UPDATE services 
        SET name = COALESCE(?, name),
            description = COALESCE(?, description),
            price = COALESCE(?, price),
            duration_minutes = COALESCE(?, duration_minutes),
            category = COALESCE(?, category),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND is_active = 1
      `).bind(
        body.name,
        body.description,
        body.price ? parseFloat(body.price) : null,
        body.duration_minutes ? parseInt(body.duration_minutes) : null,
        body.category,
        id
      ).run();
      
      if (result.success && result.meta?.changes > 0) {
        return jsonResponse({ success: true, message: 'تم تحديث الخدمة' }, 200, env);
      }
      
      return jsonResponse({ success: false, error: 'الخدمة غير موجودة' }, 404, env);
      
    } catch (error) {
      return handleError('Update Service', error);
    }
  }
  
  if (request.method === 'DELETE') {
    try {
      const result = await env.DB.prepare(`
        UPDATE services 
        SET is_active = 0, 
            updated_at = CURRENT_TIMESTAMP, 
            deleted_at = CURRENT_TIMESTAMP 
        WHERE id = ?
      `).bind(id).run();
      
      if (result.success && result.meta?.changes > 0) {
        return jsonResponse({ success: true, message: 'تم حذف الخدمة' }, 200, env);
      }
      
      return jsonResponse({ success: false, error: 'الخدمة غير موجودة' }, 404, env);
      
    } catch (error) {
      return handleError('Delete Service', error);
    }
  }
  
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
}

// =====================================================
// 10. Inventory Handlers - محسّنة
// =====================================================

async function handleInventory(request: Request, env: Env, user: any): Promise<Response> {
  if (request.method === 'GET') {
    try {
      const result = await env.DB.prepare(`
        SELECT *, 
          CASE 
            WHEN quantity <= min_stock_level THEN 'low' 
            WHEN quantity <= min_stock_level * 2 THEN 'warning' 
            ELSE 'ok' 
          END as stock_status 
        FROM inventory 
        ORDER BY category, name
      `).all();
      
      return jsonResponse({
        success: true,
        results: result.results || []
      }, 200, env);
      
    } catch (error) {
      return handleError('Get Inventory', error);
    }
  }
  
  if (request.method === 'POST') {
    try {
      const body = await request.json();
      
      const validation = validateInput(body, {
        name: { required: true, minLength: 2, maxLength: 100 },
        quantity: { required: true, type: 'number', min: 0 },
        unit_price: { required: false, type: 'number', min: 0 },
        min_stock_level: { required: false, type: 'number', min: 0 },
        category: { required: false, maxLength: 50 },
        description: { required: false, maxLength: 500 }
      });
      
      if (!validation.valid) {
        return jsonResponse({
          success: false,
          errors: validation.errors
        }, 400, env);
      }
      
      // التحقق من صحة الأرقام
      if (!isValidNumber(body.quantity) || 
          (body.unit_price !== undefined && !isValidNumber(body.unit_price)) ||
          (body.min_stock_level !== undefined && !isValidNumber(body.min_stock_level))) {
        return jsonResponse({
          success: false,
          error: 'قيم رقمية غير صالحة'
        }, 400, env);
      }
      
      const sanitized = sanitizeInput(body);
      
      const result = await env.DB.prepare(`
        INSERT INTO inventory 
        (name, description, quantity, unit_price, category, min_stock_level, created_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).bind(
        sanitized.name,
        sanitized.description || null,
        parseInt(sanitized.quantity),
        sanitized.unit_price ? parseFloat(sanitized.unit_price) : null,
        sanitized.category || null,
        sanitized.min_stock_level ? parseInt(sanitized.min_stock_level) : 0
      ).run();
      
      if (result.success) {
        // إضافة سجل لتغييرات المخزون
        await env.DB.prepare(`
          INSERT INTO inventory_changes 
          (inventory_id, change_type, quantity_change, previous_quantity, new_quantity, reason, created_by, created_at)
          VALUES (?, 'initial', ?, 0, ?, 'إضافة منتج جديد', ?, CURRENT_TIMESTAMP)
        `).bind(
          result.meta?.last_row_id,
          parseInt(sanitized.quantity),
          parseInt(sanitized.quantity),
          user.id
        ).run();
        
        return jsonResponse({
          success: true,
          id: result.meta?.last_row_id,
          message: 'تم إضافة المنتج بنجاح'
        }, 201, env);
      }
      
      return jsonResponse({ success: false, error: 'فشل في إضافة المنتج' }, 400, env);
      
    } catch (error) {
      return handleError('Create Inventory', error);
    }
  }
  
  // دعم PUT المباشر للتوافق مع الكود الأصلي
  if (request.method === 'PUT') {
    try {
      const body = await request.json();
      const { id, quantity, reason } = body;
      
      if (!id || quantity === undefined) {
        return jsonResponse({
          success: false,
          error: 'معرف المنتج والكمية مطلوبان'
        }, 400, env);
      }
      
      // التحقق من صحة الكمية
      if (!isValidNumber(quantity)) {
        return jsonResponse({
          success: false,
          error: 'الكمية غير صالحة'
        }, 400, env);
      }
      
      // الحصول على الكمية الحالية
      const current = await env.DB.prepare(`
        SELECT quantity FROM inventory WHERE id = ?
      `).bind(id).first();
      
      if (!current) {
        return jsonResponse({ success: false, error: 'المنتج غير موجود' }, 404, env);
      }
      
      const previousQuantity = current.quantity;
      const newQuantity = parseInt(quantity);
      const changeType = newQuantity > previousQuantity ? 'increase' : 
                         newQuantity < previousQuantity ? 'decrease' : 'no_change';
      
      const result = await env.DB.prepare(`
        UPDATE inventory 
        SET quantity = ?, 
            updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
      `).bind(newQuantity, id).run();
      
      if (result.success && result.meta?.changes > 0) {
        // إضافة سجل لتغييرات المخزون
        await env.DB.prepare(`
          INSERT INTO inventory_changes 
          (inventory_id, change_type, quantity_change, previous_quantity, new_quantity, reason, created_by, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `).bind(
          id,
          changeType,
          newQuantity - previousQuantity,
          previousQuantity,
          newQuantity,
          reason || 'تحديث الكمية',
          user.id
        ).run();
        
        return jsonResponse({ success: true, message: 'تم تحديث الكمية' }, 200, env);
      }
      
      return jsonResponse({ success: false, error: 'فشل في تحديث الكمية' }, 400, env);
      
    } catch (error) {
      return handleError('Update Inventory Quantity', error);
    }
  }
  
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
}

async function handleInventoryById(request: Request, env: Env, user: any, id: string): Promise<Response> {
  if (request.method === 'GET') {
    try {
      const item = await env.DB.prepare(`
        SELECT *, 
          CASE 
            WHEN quantity <= min_stock_level THEN 'low' 
            WHEN quantity <= min_stock_level * 2 THEN 'warning' 
            ELSE 'ok' 
          END as stock_status 
        FROM inventory 
        WHERE id = ?
      `).bind(id).first();
      
      if (!item) {
        return jsonResponse({ success: false, error: 'المنتج غير موجود' }, 404, env);
      }
      
      // الحصول على سجل التغييرات
      const changes = await env.DB.prepare(`
        SELECT 
          ic.*,
          u.full_name as user_name
        FROM inventory_changes ic
        LEFT JOIN users u ON ic.created_by = u.id
        WHERE ic.inventory_id = ?
        ORDER BY ic.created_at DESC
        LIMIT 10
      `).bind(id).all();
      
      return jsonResponse({ 
        success: true, 
        data: {
          ...item,
          changes: changes.results || []
        } 
      }, 200, env);
      
    } catch (error) {
      return handleError('Get Inventory Item', error);
    }
  }
  
  if (request.method === 'PUT') {
    try {
      const body = await request.json();
      
      const validation = validateInput(body, {
        name: { required: false, minLength: 2, maxLength: 100 },
        quantity: { required: false, type: 'number', min: 0 },
        unit_price: { required: false, type: 'number', min: 0 },
        min_stock_level: { required: false, type: 'number', min: 0 },
        category: { required: false, maxLength: 50 },
        description: { required: false, maxLength: 500 }
      });
      
      if (!validation.valid) {
        return jsonResponse({
          success: false,
          errors: validation.errors
        }, 400, env);
      }
      
      // التحقق من صحة الأرقام
      if ((body.quantity !== undefined && !isValidNumber(body.quantity)) || 
          (body.unit_price !== undefined && !isValidNumber(body.unit_price)) ||
          (body.min_stock_level !== undefined && !isValidNumber(body.min_stock_level))) {
        return jsonResponse({
          success: false,
          error: 'قيم رقمية غير صالحة'
        }, 400, env);
      }
      
      // الحصول على البيانات الحالية
      const current = await env.DB.prepare(`
        SELECT quantity FROM inventory WHERE id = ?
      `).bind(id).first();
      
      if (!current) {
        return jsonResponse({ success: false, error: 'المنتج غير موجود' }, 404, env);
      }
      
      const previousQuantity = current.quantity;
      const newQuantity = body.quantity !== undefined ? parseInt(body.quantity) : previousQuantity;
      
      const result = await env.DB.prepare(`
        UPDATE inventory 
        SET name = COALESCE(?, name),
            description = COALESCE(?, description),
            quantity = COALESCE(?, quantity),
            unit_price = COALESCE(?, unit_price),
            category = COALESCE(?, category),
            min_stock_level = COALESCE(?, min_stock_level),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(
        body.name,
        body.description,
        newQuantity,
        body.unit_price ? parseFloat(body.unit_price) : null,
        body.category,
        body.min_stock_level ? parseInt(body.min_stock_level) : null,
        id
      ).run();
      
      if (result.success && result.meta?.changes > 0) {
        // إذا تم تغيير الكمية، أضف سجل التغيير
        if (body.quantity !== undefined && newQuantity !== previousQuantity) {
          const changeType = newQuantity > previousQuantity ? 'increase' : 
                             newQuantity < previousQuantity ? 'decrease' : 'no_change';
          
          await env.DB.prepare(`
            INSERT INTO inventory_changes 
            (inventory_id, change_type, quantity_change, previous_quantity, new_quantity, reason, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
          `).bind(
            id,
            changeType,
            newQuantity - previousQuantity,
            previousQuantity,
            newQuantity,
            'تحديث المنتج',
            user.id
          ).run();
        }
        
        return jsonResponse({ success: true, message: 'تم تحديث المنتج' }, 200, env);
      }
      
      return jsonResponse({ success: false, error: 'المنتج غير موجود' }, 404, env);
      
    } catch (error) {
      return handleError('Update Inventory', error);
    }
  }
  
  if (request.method === 'DELETE') {
    try {
      const result = await env.DB.prepare(`DELETE FROM inventory WHERE id = ?`).bind(id).run();
      
      if (result.success && result.meta?.changes > 0) {
        return jsonResponse({ success: true, message: 'تم حذف المنتج' }, 200, env);
      }
      
      return jsonResponse({ success: false, error: 'المنتج غير موجود' }, 404, env);
      
    } catch (error) {
      return handleError('Delete Inventory', error);
    }
  }
  
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
}

// =====================================================
// 11. Users Handler - محسّنة
// =====================================================

async function handleUsers(request: Request, env: Env, user: any): Promise<Response> {
  if (request.method === 'GET') {
    try {
      const result = await env.DB.prepare(`
        SELECT 
          id,
          full_name,
          email,
          phone,
          role,
          avatar_url,
          is_active,
          created_at
        FROM users 
        WHERE is_active = 1 
        ORDER BY role, full_name
      `).all();
      
      return jsonResponse({
        success: true,
        results: result.results || []
      }, 200, env);
      
    } catch (error) {
      return handleError('Get Users', error);
    }
  }
  
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
}

// =====================================================
// 12. Dashboard Handler - محسّنة
// =====================================================

async function handleDashboard(request: Request, env: Env, user: any): Promise<Response> {
  if (request.method !== 'GET') {
    return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
  }
  
  try {
    const now = new Date();
    const today = now.toISOString().split('T')[0];
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
    const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().split('T')[0];
    
    // جمع الإحصائيات بشكل متوازي
    const [
      customersCount,
      servicesCount,
      todayAppointments,
      lowStock,
      monthlyStats,
      recentAppointments,
      recentTransactions,
      topServices,
      topCustomers
    ] = await Promise.all([
      // عدد العملاء النشطين
      env.DB.prepare('SELECT COUNT(*) as count FROM customers WHERE is_active = 1').first(),
      
      // عدد الخدمات
      env.DB.prepare('SELECT COUNT(*) as count FROM services WHERE is_active = 1').first(),
      
      // مواعيد اليوم
      env.DB.prepare(`
        SELECT COUNT(*) as count 
        FROM appointments 
        WHERE date(appointment_date) = ? 
        AND status IN ('scheduled', 'confirmed')
      `).bind(today).first(),
      
      // المخزون المنخفض
      env.DB.prepare(`
        SELECT COUNT(*) as count 
        FROM inventory 
        WHERE quantity <= min_stock_level
      `).first(),
      
      // إحصائيات الشهر
      env.DB.prepare(`
        SELECT 
          SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as income,
          SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as expense,
          COUNT(*) as total_transactions,
          COUNT(DISTINCT date) as active_days
        FROM transactions 
        WHERE date BETWEEN ? AND ?
      `).bind(firstDay, lastDay).first(),
      
      // آخر المواعيد
      env.DB.prepare(`
        SELECT 
          a.*,
          c.full_name as customer_name,
          s.name as service_name,
          u.full_name as employee_name
        FROM appointments a
        LEFT JOIN customers c ON a.customer_id = c.id
        LEFT JOIN services s ON a.service_id = s.id
        LEFT JOIN users u ON a.employee_id = u.id
        WHERE date(a.appointment_date) >= ?
        ORDER BY a.appointment_date DESC
        LIMIT 10
      `).bind(today).all(),
      
      // آخر المعاملات
      env.DB.prepare(`
        SELECT * FROM transactions
        ORDER BY created_at DESC
        LIMIT 10
      `).all(),
      
      // أكثر الخدمات طلباً
      env.DB.prepare(`
        SELECT 
          s.name,
          COUNT(a.id) as count,
          SUM(CASE WHEN a.status = 'completed' THEN a.price ELSE 0 END) as revenue
        FROM services s
        JOIN appointments a ON s.id = a.service_id
        WHERE a.appointment_date BETWEEN ? AND ?
        AND a.status = 'completed'
        GROUP BY s.id
        ORDER BY count DESC
        LIMIT 5
      `).bind(firstDay, lastDay).all(),
      
      // أفضل العملاء
      env.DB.prepare(`
        SELECT 
          c.full_name,
          COUNT(a.id) as visits,
          SUM(CASE WHEN a.status = 'completed' THEN a.price ELSE 0 END) as total_spent
        FROM customers c
        JOIN appointments a ON c.id = a.customer_id
        WHERE a.appointment_date BETWEEN ? AND ?
        AND a.status = 'completed'
        GROUP BY c.id
        ORDER BY total_spent DESC
        LIMIT 5
      `).bind(firstDay, lastDay).all()
    ]);
    
    return jsonResponse({
      success: true,
      data: {
        stats: {
          totalCustomers: customersCount?.count || 0,
          totalServices: servicesCount?.count || 0,
          todayAppointments: todayAppointments?.count || 0,
          lowStockItems: lowStock?.count || 0,
          monthlyIncome: monthlyStats?.income || 0,
          monthlyExpense: monthlyStats?.expense || 0,
          monthlyProfit: (monthlyStats?.income || 0) - (monthlyStats?.expense || 0),
          totalTransactions: monthlyStats?.total_transactions || 0,
          activeDays: monthlyStats?.active_days || 0
        },
        recentAppointments: recentAppointments?.results || [],
        recentTransactions: recentTransactions?.results || [],
        topServices: topServices?.results || [],
        topCustomers: topCustomers?.results || [],
        period: {
          today,
          monthStart: firstDay,
          monthEnd: lastDay
        }
      }
    }, 200, env);
    
  } catch (error) {
    return handleError('Dashboard', error);
  }
}

// =====================================================
// 13. Reports Handler - محسّنة
// =====================================================

async function handleReports(request: Request, env: Env, user: any): Promise<Response> {
  const { searchParams } = new URL(request.url);
  const reportType = searchParams.get('type');
  const startDate = searchParams.get('start_date');
  const endDate = searchParams.get('end_date');
  const format = searchParams.get('format') || 'json';
  
  if (request.method !== 'GET') {
    return jsonResponse({ success: false, error: 'Method not allowed' }, 405, env);
  }
  
  if (!reportType || !startDate || !endDate) {
    return jsonResponse({
      success: false,
      error: 'نوع التقرير والتواريخ مطلوبة'
    }, 400, env);
  }
  
  // التحقق من صحة التواريخ
  if (!isValidDate(startDate) || !isValidDate(endDate)) {
    return jsonResponse({
      success: false,
      error: 'تواريخ غير صالحة'
    }, 400, env);
  }
  
  try {
    let result;
    
    switch (reportType) {
      case 'revenue':
        // تقرير الإيرادات التفصيلي
        result = await env.DB.prepare(`
          SELECT 
            date,
            SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as income,
            SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as expense,
            SUM(CASE WHEN type = 'income' THEN amount ELSE -amount END) as profit,
            COUNT(*) as transaction_count,
            GROUP_CONCAT(DISTINCT category) as categories
          FROM transactions
          WHERE date BETWEEN ? AND ?
          GROUP BY date
          ORDER BY date DESC
        `).bind(startDate, endDate).all();
        break;
        
      case 'services':
        // تقرير أداء الخدمات
        result = await env.DB.prepare(`
          SELECT 
            s.id,
            s.name,
            s.category,
            s.price as base_price,
            COUNT(a.id) as appointment_count,
            COUNT(DISTINCT a.customer_id) as unique_customers,
            COUNT(DISTINCT a.employee_id) as employees_provided,
            SUM(CASE WHEN a.status = 'completed' THEN a.price ELSE 0 END) as total_revenue,
            AVG(CASE WHEN a.status = 'completed' THEN a.price END) as avg_price,
            MIN(CASE WHEN a.status = 'completed' THEN a.price END) as min_price,
            MAX(CASE WHEN a.status = 'completed' THEN a.price END) as max_price,
            COUNT(CASE WHEN a.status = 'completed' THEN 1 END) as completed,
            COUNT(CASE WHEN a.status = 'cancelled' THEN 1 END) as cancelled
          FROM services s
          LEFT JOIN appointments a ON s.id = a.service_id
            AND a.appointment_date BETWEEN ? AND ?
          WHERE s.is_active = 1
          GROUP BY s.id
          ORDER BY total_revenue DESC
        `).bind(startDate, endDate).all();
        break;
        
      case 'employees':
        // تقرير أداء الموظفين
        result = await env.DB.prepare(`
          SELECT 
            u.id,
            u.full_name,
            u.role,
            COUNT(a.id) as total_appointments,
            COUNT(CASE WHEN a.status = 'completed' THEN 1 END) as completed,
            COUNT(CASE WHEN a.status = 'cancelled' THEN 1 END) as cancelled,
            COUNT(CASE WHEN a.status = 'scheduled' THEN 1 END) as scheduled,
            COUNT(DISTINCT a.customer_id) as unique_customers,
            COUNT(DISTINCT a.service_id) as services_provided,
            SUM(CASE WHEN a.status = 'completed' THEN a.price ELSE 0 END) as total_revenue,
            AVG(CASE WHEN a.status = 'completed' THEN a.price END) as avg_service_value,
            MAX(a.appointment_date) as last_appointment
          FROM users u
          LEFT JOIN appointments a ON u.id = a.employee_id
            AND a.appointment_date BETWEEN ? AND ?
          WHERE u.is_active = 1
          GROUP BY u.id
          ORDER BY total_revenue DESC
        `).bind(startDate, endDate).all();
        break;
        
      case 'customers':
        // تقرير تحليل العملاء
        result = await env.DB.prepare(`
          SELECT 
            c.id,
            c.full_name,
            c.phone,
            c.email,
            COUNT(a.id) as visit_count,
            COUNT(DISTINCT a.service_id) as services_used,
            COUNT(DISTINCT a.employee_id) as employees_seen,
            SUM(CASE WHEN a.status = 'completed' THEN a.price ELSE 0 END) as total_spent,
            AVG(CASE WHEN a.status = 'completed' THEN a.price END) as avg_per_visit,
            MIN(a.appointment_date) as first_visit,
            MAX(a.appointment_date) as last_visit,
            COUNT(CASE WHEN a.status = 'cancelled' THEN 1 END) as cancelled_count
          FROM customers c
          LEFT JOIN appointments a ON c.id = a.customer_id
            AND a.appointment_date BETWEEN ? AND ?
          WHERE c.is_active = 1
          GROUP BY c.id
          HAVING visit_count > 0
          ORDER BY total_spent DESC
        `).bind(startDate, endDate).all();
        break;
        
      case 'inventory':
        // تقرير المخزون
        result = await env.DB.prepare(`
          SELECT 
            name,
            category,
            quantity,
            unit_price,
            quantity * unit_price as total_value,
            min_stock_level,
            CASE 
              WHEN quantity = 0 THEN 'نفذ'
              WHEN quantity <= min_stock_level THEN 'منخفض'
              WHEN quantity <= min_stock_level * 2 THEN 'تحذير'
              ELSE 'جيد'
            END as status
          FROM inventory
          ORDER BY status DESC, category, name
        `).all();
        break;
        
      default:
        return jsonResponse({ 
          success: false, 
          error: 'نوع التقرير غير صحيح',
          availableTypes: ['revenue', 'services', 'employees', 'customers', 'inventory']
        }, 400, env);
    }
    
    // إضافة ملخص للتقرير
    const summary = {
      revenue: {
        totalIncome: 0,
        totalExpense: 0,
        netProfit: 0
      },
      counts: {
        totalRecords: result?.results?.length || 0
      }
    };
    
    if (reportType === 'revenue' && result?.results) {
      summary.revenue = result.results.reduce((acc, row) => ({
        totalIncome: acc.totalIncome + (row.income || 0),
        totalExpense: acc.totalExpense + (row.expense || 0),
        netProfit: acc.netProfit + (row.profit || 0)
      }), summary.revenue);
    }
    
    return jsonResponse({
      success: true,
      reportType,
      period: { startDate, endDate },
      summary,
      results: result?.results || [],
      count: result?.results?.length || 0,
      generatedAt: new Date().toISOString()
    }, 200, env);
    
  } catch (error) {
    return handleError('Reports', error);
  }
}

// =====================================================
// 14. Login Page HTML - محسّنة
// =====================================================

function getLoginPageHTML(): string {
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;">
    <title>سهل - نظام إدارة الصالون</title>
    <style>
        /* CSS styles remain the same */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, 'Segoe UI', 'Tahoma', 'Arial', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            width: 100%;
            max-width: 420px;
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
            animation: fadeIn 0.8s ease;
        }
        
        .logo h1 {
            color: white;
            font-size: 48px;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .logo p {
            color: rgba(255,255,255,0.9);
            margin-top: 10px;
            font-size: 16px;
        }
        
        .login-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
            animation: slideUp 0.5s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .form-container {
            padding: 40px 30px;
        }
        
        .form-title {
            text-align: center;
            color: #333;
            font-size: 24px;
            margin-bottom: 30px;
            font-weight: 600;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
            font-size: 14px;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s;
            font-family: inherit;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .form-group input.error {
            border-color: #f44336;
        }
        
        .password-wrapper {
            position: relative;
        }
        
        .toggle-password {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #999;
            font-size: 20px;
        }
        
        .alert {
            padding: 12px 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: none;
            animation: slideDown 0.3s ease;
        }
        
        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .alert.show {
            display: block;
        }
        
        .alert.success {
            background: #e8f5e9;
            color: #2e7d32;
            border: 1px solid #4caf50;
        }
        
        .alert.error {
            background: #ffebee;
            color: #c62828;
            border: 1px solid #f44336;
        }
        
        .btn-submit {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        
        .btn-submit:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }
        
        .btn-submit:active {
            transform: translateY(0);
        }
        
        .btn-submit:disabled {
            opacity: 0.7;
            cursor: not-allowed;
        }
        
        .loading {
            display: none;
            width: 20px;
            height: 20px;
            border: 2px solid white;
            border-top-color: transparent;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .btn-submit.loading .btn-text {
            display: none;
        }
        
        .btn-submit.loading .loading {
            display: block;
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            color: rgba(255,255,255,0.8);
            font-size: 14px;
        }
        
        .demo-info {
            background: #f5f5f5;
            border-radius: 10px;
            padding: 15px;
            margin-top: 20px;
            border: 1px solid #e0e0e0;
        }
        
        .demo-info h4 {
            color: #666;
            margin-bottom: 10px;
            font-size: 14px;
        }
        
        .demo-info p {
            color: #888;
            font-size: 13px;
            margin: 5px 0;
        }
        
        .demo-info code {
            background: white;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: #e91e63;
        }
        
        @media (max-width: 480px) {
            .logo h1 {
                font-size: 36px;
            }
            
            .form-container {
                padding: 30px 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>سهل</h1>
            <p>نظام إدارة الصالون المتكامل</p>
        </div>
        
        <div class="login-card">
            <div class="form-container">
                <h2 class="form-title">تسجيل الدخول</h2>
                
                <div class="alert" id="alert"></div>
                
                <form id="loginForm">
                    <div class="form-group">
                        <label for="email">البريد الإلكتروني</label>
                        <input 
                            type="email" 
                            id="email" 
                            name="email" 
                            required
                            placeholder="example@sahl.com"
                            autocomplete="email"
                        >
                    </div>
                    
                    <div class="form-group">
                        <label for="password">كلمة المرور</label>
                        <div class="password-wrapper">
                            <input 
                                type="password" 
                                id="password" 
                                name="password" 
                                required
                                placeholder="••••••••"
                                autocomplete="current-password"
                            >
                            <span class="toggle-password" onclick="togglePassword()">👁</span>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn-submit" id="submitBtn">
                        <span class="btn-text">دخول</span>
                        <div class="loading"></div>
                    </button>
                </form>
                
                <div class="demo-info">
                    <h4>🔐 حساب تجريبي للدخول:</h4>
                    <p>البريد: <code>admin@sahl.com</code></p>
                    <p>كلمة المرور: <code>admin123</code></p>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>© 2024 سهل - جميع الحقوق محفوظة</p>
        </div>
    </div>
    
    <script>
        function togglePassword() {
            const passwordInput = document.getElementById('password');
            const toggleBtn = document.querySelector('.toggle-password');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggleBtn.textContent = '👁‍🗨';
            } else {
                passwordInput.type = 'password';
                toggleBtn.textContent = '👁';
            }
        }
        
        function showAlert(message, type) {
            const alert = document.getElementById('alert');
            alert.className = 'alert show ' + type;
            alert.textContent = message;
            
            setTimeout(() => {
                alert.classList.remove('show');
            }, 5000);
        }
        
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const submitBtn = document.getElementById('submitBtn');
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            // Validation
            if (!email || !password) {
                showAlert('يرجى ملء جميع الحقول', 'error');
                return;
            }
            
            if (password.length < 6) {
                showAlert('كلمة المرور يجب أن تكون 6 أحرف على الأقل', 'error');
                return;
            }
            
            // Show loading
            submitBtn.classList.add('loading');
            submitBtn.disabled = true;
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showAlert('تم تسجيل الدخول بنجاح! جاري التحويل...', 'success');
                    
                    // Store token
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('user', JSON.stringify(data.user));
                    
                    // Redirect to dashboard
                    setTimeout(() => {
                        window.location.href = '/dashboard';
                    }, 1500);
                } else {
                    showAlert(data.error || 'فشل تسجيل الدخول', 'error');
                }
            } catch (error) {
                showAlert('حدث خطأ في الاتصال بالخادم', 'error');
                console.error('Login error:', error);
            } finally {
                submitBtn.classList.remove('loading');
                submitBtn.disabled = false;
            }
        });
        
        // Auto-fill demo credentials on click
        document.querySelector('.demo-info').addEventListener('click', () => {
            document.getElementById('email').value = 'admin@sahl.com';
            document.getElementById('password').value = 'admin123';
            showAlert('تم ملء بيانات الحساب التجريبي', 'success');
        });
        
        // Check if already logged in
        window.addEventListener('load', async () => {
            const token = localStorage.getItem('token');
            if (token) {
                try {
                    const response = await fetch('/api/auth/verify', {
                        headers: {
                            'Authorization': 'Bearer ' + token
                        }
                    });
                    
                    const data = await response.json();
                    if (data.valid) {
                        window.location.href = '/dashboard';
                    }
                } catch (error) {
                    console.error('Token verification error:', error);
                }
            }
        });
    </script>
</body>
</html>`;
}

// =====================================================
// النهاية - End of Enhanced Worker
// =====================================================
