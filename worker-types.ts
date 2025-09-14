// worker-types.ts
// تعريفات الأنواع لنظام سهل - إدارة الصالون المتكامل
// =====================================================
// 1. Environment Types
// =====================================================
export interface Env {
  // Required
  DB: D1Database;
  ASSETS: Fetcher;
  JWT_SECRET: string;
  
  // Optional services
  R2_BUCKET?: R2Bucket;
  KV?: KVNamespace;
  
  // Configuration
  CORS_ORIGINS?: string;
  RATE_LIMIT_REQUESTS?: string;
  SESSION_DURATION?: string;
}

// =====================================================
// 2. Database Models
// =====================================================
export interface User {
  id: number;
  full_name: string;
  email: string;
  phone?: string;
  role: 'admin' | 'employee' | 'manager';
  password_hash?: string;
  password_salt?: string;
  avatar_url?: string;
  is_active: number;
  created_at: string;
  updated_at: string;
}

export interface Customer {
  id: number;
  full_name: string;
  phone?: string;
  email?: string;
  notes?: string;
  is_active: number;
  created_at: string;
  updated_at: string;
  created_by?: number;
  
  // Computed fields (from JOINs)
  appointment_count?: number;
  total_spent?: number;
}

export interface Service {
  id: number;
  name: string;
  description?: string;
  price: number;
  duration_minutes: number;
  category?: string;
  is_active: number;
  created_at: string;
  updated_at: string;
  
  // Computed fields
  appointment_count?: number;
  total_revenue?: number;
}

export interface Appointment {
  id: number;
  customer_id: number;
  service_id: number;
  employee_id?: number;
  appointment_date: string;
  status: 'scheduled' | 'confirmed' | 'completed' | 'cancelled';
  notes?: string;
  price?: number;
  created_at: string;
  updated_at: string;
  created_by?: number;
  
  // JOIN fields
  customer_name?: string;
  customer_phone?: string;
  customer_email?: string;
  service_name?: string;
  duration_minutes?: number;
  service_price?: number;
  employee_name?: string;
}

export interface Transaction {
  id: number;
  type: 'income' | 'expense';
  category: string;
  amount: number;
  description?: string;
  date: string;
  appointment_id?: number;
  receipt_url?: string;
  created_by?: number;
  created_at: string;
  
  // JOIN fields
  created_by_name?: string;
}

export interface InventoryItem {
  id: number;
  name: string;
  description?: string;
  quantity: number;
  unit_price?: number;
  category?: string;
  min_stock_level: number;
  created_at: string;
  updated_at: string;
  
  // ✅ تصحيح: استخدام الإنجليزية كما في معظم الكود
  stock_status?: 'ok' | 'warning' | 'low';
  total_value?: number;
  changes?: InventoryChange[];
}

export interface InventoryChange {
  id: number;
  inventory_id: number;
  change_type: 'initial' | 'increase' | 'decrease' | 'no_change';
  quantity_change: number;
  previous_quantity: number;
  new_quantity: number;
  reason?: string;
  created_by: number;
  created_at: string;
  
  // JOIN fields
  user_name?: string;
}

// =====================================================
// 3. API Request/Response Types
// =====================================================
export interface AuthRequest {
  email: string;
  password: string;
}

export interface RegisterRequest extends AuthRequest {
  full_name: string;
  phone?: string;
  role?: 'admin' | 'employee' | 'manager';
}

export interface AuthResponse {
  success: boolean;
  token?: string;
  user?: {
    id: number;
    name: string;
    email: string;
    role: string;
  };
  message?: string;
  error?: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  results?: T[];
  count?: number;
  total?: number;
  message?: string;
  error?: string;
  errors?: string[];
  errorId?: string;
  code?: string;
  context?: string;
  pagination?: {
    limit: number;
    offset: number;
  };
  period?: {
    start?: string;
    end?: string;
    today?: string;
    monthStart?: string;
    monthEnd?: string;
  };
  generatedAt?: string;
  reportType?: string;
  summary?: any;
  totals?: {
    total_income?: number;
    total_expense?: number;
    net_profit?: number;
  };
}

export interface DashboardData {
  stats: {
    totalCustomers: number;
    totalServices: number;
    todayAppointments: number;
    lowStockItems: number;
    monthlyIncome: number;
    monthlyExpense: number;
    monthlyProfit: number;
    totalTransactions: number;
    activeDays: number;
  };
  recentAppointments: Appointment[];
  recentTransactions: Transaction[];
  topServices: Array<{
    name: string;
    count: number;
    revenue: number;
  }>;
  topCustomers: Array<{
    full_name: string;
    visits: number;
    total_spent: number;
  }>;
  // ✅ تصحيح: إكمال تعريف monthEnd
  period: {
    today: string;
    monthStart: string;
    monthEnd?: string;
  };
}

export interface ReportRequest {
  type: 'revenue' | 'services' | 'employees' | 'customers' | 'inventory';
  start_date: string;
  end_date: string;
  format?: 'json';
}

// =====================================================
// 4. Authentication & Security Types
// =====================================================
export interface JWTPayload {
  id: number;
  email: string;
  name: string;
  role: string;
  iat: number;
  exp: number;
}

export interface AuthenticatedUser {
  id: number;
  email: string;
  name: string;
  role: string;
}

export interface AuthenticationResult {
  valid: boolean;
  user?: AuthenticatedUser;
}

// =====================================================
// 5. Validation Types
// =====================================================
export interface ValidationRule {
  required?: boolean;
  type?: 'email' | 'number' | 'date' | 'string';
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  enum?: string[];
  pattern?: RegExp;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

// =====================================================
// 6. File Upload Types
// =====================================================
export interface FileUploadRequest {
  file: File;
  type: 'avatar' | 'receipt';
  relatedId?: string;  // user_id for avatar, transaction_id for receipt
}

export interface FileUploadResponse {
  success: boolean;
  url?: string;
  filename?: string;
  message?: string;
  error?: string;
}

// =====================================================
// 7. Search & Filter Types
// =====================================================
export interface SearchParams {
  search?: string;
  limit?: number;
  offset?: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

export interface DateRangeParams {
  start_date: string;
  end_date: string;
}

export interface TransactionSummary {
  type: string;
  category: string;
  count: number;
  total: number;
  average: number;
}

// =====================================================
// 8. Helper Types
// =====================================================
export type HTTPMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS';

export interface RouteHandler {
  (request: Request, env: Env, user?: AuthenticatedUser): Promise<Response>;
}

export interface MiddlewareResult {
  continue: boolean;
  response?: Response;
  data?: any;
}

// =====================================================
// 9. Report Types
// =====================================================
export interface RevenueReport {
  date: string;
  income: number;
  expense: number;
  profit: number;
  transaction_count: number;
  categories: string;
}

export interface ServiceReport {
  id: number;
  name: string;
  category?: string;
  base_price: number;
  appointment_count: number;
  unique_customers: number;
  employees_provided: number;
  total_revenue: number;
  avg_price: number;
  min_price: number;
  max_price: number;
  completed: number;
  cancelled: number;
}

export interface EmployeeReport {
  id: number;
  full_name: string;
  role: string;
  total_appointments: number;
  completed: number;
  cancelled: number;
  scheduled: number;
  unique_customers: number;
  services_provided: number;
  total_revenue: number;
  avg_service_value: number;
  last_appointment: string;
}

export interface CustomerReport {
  id: number;
  full_name: string;
  phone?: string;
  email?: string;
  visit_count: number;
  services_used: number;
  employees_seen: number;
  total_spent: number;
  avg_per_visit: number;
  first_visit: string;
  last_visit: string;
  cancelled_count: number;
}

export interface InventoryReport {
  name: string;
  category?: string;
  quantity: number;
  unit_price?: number;
  total_value?: number;
  min_stock_level: number;
  status: string;  // 'نفذ' | 'منخفض' | 'تحذير' | 'جيد'
}

// =====================================================
// 10. Error Types
// =====================================================
export enum ErrorCode {
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  NOT_FOUND = 'NOT_FOUND',
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  INTERNAL_ERROR = 'INTERNAL_ERROR'
}

export interface AppError {
  code: ErrorCode | string;
  message: string;
  context?: string;
  errorId?: string;
  timestamp?: string;
  details?: any;
}

export interface RateLimitInfo {
  limit: number;
  remaining: number;
  reset: number;
}

// =====================================================
// 11. Health Check Types
// =====================================================
export interface HealthStatus {
  success: boolean;
  status: string;  // حالياً 'healthy' لكن قد يتغير
  system: string;
  version: string;
  timestamp: string;
}
