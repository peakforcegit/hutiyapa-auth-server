import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from "@nestjs/common";
import { Observable, tap } from "rxjs";
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest();
    const start = Date.now();
    return next.handle().pipe(tap(() => {
      const _ms = Date.now() - start;
      const _method = req?.method;
      const _url = req?.originalUrl || req?.url;
    }));
  }
}
