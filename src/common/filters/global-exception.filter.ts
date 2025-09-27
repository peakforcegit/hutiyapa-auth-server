import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

interface ErrorResponse {
  success: false;
  error: {
    message: string;
    code: string;
    statusCode: number;
    timestamp: string;
    path: string;
    requestId?: string;
    details?: any;
  };
}

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    // Short-circuit CSRF errors with minimal body and 403 status
    if (
      exception &&
      typeof exception === 'object' &&
      ((exception as any).code === 'EBADCSRFTOKEN' ||
        ((exception as any).name === 'ForbiddenError' &&
          (exception as any).message?.toLowerCase?.().includes('csrf')))
    ) {
      const requestId =
        (request.headers['x-request-id'] as string) ||
        (response.getHeader('x-request-id') as string) ||
        this.generateRequestId();

      response.setHeader('x-request-id', requestId);
      response.status(HttpStatus.FORBIDDEN).json({ error: 'Invalid CSRF token' });
      return;
    }

    const { status, message, code, details } = this.extractErrorInfo(exception);

    // Generate correlation ID if not present
    const requestId = (request.headers['x-request-id'] as string) || 
                     response.getHeader('x-request-id') as string ||
                     this.generateRequestId();

    const errorResponse: ErrorResponse = {
      success: false,
      error: {
        message: this.sanitizeErrorMessage(message, status),
        code,
        statusCode: status,
        timestamp: new Date().toISOString(),
        path: request.url,
        requestId,
        ...(process.env.NODE_ENV !== 'production' && details && { details }),
      },
    };

    // Log the error with appropriate level
    const logContext = {
      method: request.method,
      url: request.url,
      ip: this.getClientIp(request),
      userAgent: request.headers['user-agent'],
      requestId,
      statusCode: status,
      error: message,
      stack: exception instanceof Error ? exception.stack : undefined,
    };

    if (status >= 500) {
      this.logger.error('Internal server error', logContext);
    } else if (status >= 400) {
      this.logger.warn('Client error', logContext);
    } else {
      this.logger.log('Request completed with error', logContext);
    }

    // Set correlation header
    response.setHeader('x-request-id', requestId);

    response.status(status).json(errorResponse);
  }

  private extractErrorInfo(exception: unknown): {
    status: number;
    message: string;
    code: string;
    details?: any;
  } {
    // Handle CSRF errors thrown by csurf (express middleware)
    if (
      exception &&
      typeof exception === 'object' &&
      (exception as any).code === 'EBADCSRFTOKEN'
    ) {
      return {
        status: HttpStatus.FORBIDDEN,
        message: 'Invalid CSRF token',
        code: 'FORBIDDEN',
      };
    }

    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const response = exception.getResponse();
      
      if (typeof response === 'object' && response !== null) {
        return {
          status,
          message: (response as any).message || exception.message,
          code: this.getErrorCode(status, (response as any).error),
          details: response,
        };
      }
      
      return {
        status,
        message: exception.message,
        code: this.getErrorCode(status),
      };
    }

    if (exception instanceof Error) {
      return {
        status: HttpStatus.INTERNAL_SERVER_ERROR,
        message:
          (exception as any)?.name === 'ForbiddenError' &&
          (exception as any)?.message?.toLowerCase()?.includes('csrf')
            ? 'Invalid CSRF token'
            : exception.message,
        code:
          (exception as any)?.name === 'ForbiddenError' &&
          (exception as any)?.message?.toLowerCase()?.includes('csrf')
            ? 'FORBIDDEN'
            : 'INTERNAL_SERVER_ERROR',
        details:
          process.env.NODE_ENV !== 'production'
            ? { name: exception.name, stack: exception.stack }
            : undefined,
      };
    }

    return {
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      message: 'An unexpected error occurred',
      code: 'UNKNOWN_ERROR',
      details: { exception: String(exception) },
    };
  }

  private getErrorCode(status: number, error?: string): string {
    if (error) return error.toUpperCase().replace(/\s+/g, '_');
    
    const codeMap: Record<number, string> = {
      400: 'BAD_REQUEST',
      401: 'UNAUTHORIZED', 
      403: 'FORBIDDEN',
      404: 'NOT_FOUND',
      409: 'CONFLICT',
      422: 'UNPROCESSABLE_ENTITY',
      429: 'TOO_MANY_REQUESTS',
      500: 'INTERNAL_SERVER_ERROR',
      502: 'BAD_GATEWAY',
      503: 'SERVICE_UNAVAILABLE',
    };

    return codeMap[status] || 'UNKNOWN_ERROR';
  }

  private sanitizeErrorMessage(message: any, status: number): string {
    // Don't expose sensitive error details in production for 5xx errors
    if (process.env.NODE_ENV === 'production' && status >= 500) {
      return 'Internal server error occurred. Please try again later.';
    }

    // Ensure message is a string
    const messageStr = typeof message === 'string' ? message : String(message);

    // Sanitize common sensitive patterns
    const sanitizedMessage = messageStr
      .replace(/password/gi, '[REDACTED]')
      .replace(/token/gi, '[REDACTED]')
      .replace(/secret/gi, '[REDACTED]')
      .replace(/key/gi, '[REDACTED]');

    return sanitizedMessage;
  }

  private getClientIp(request: Request): string {
    return (
      (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      request.socket.remoteAddress ||
      'unknown'
    );
  }

  private generateRequestId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
  }
}