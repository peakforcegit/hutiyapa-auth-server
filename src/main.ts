import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { ValidationPipe as GlobalValidationPipe } from './common/pipes/validation.pipe';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const enableHelmet = (process.env.ENABLE_HELMET ?? 'true') === 'true';
  const corsOrigin = process.env.CORS_ORIGIN ?? '*';
  const cookieSecret = process.env.COOKIE_SECRET ?? 'change-me';
  if (enableHelmet) {
    app.use(helmet());
  }
  app.enableCors({ origin: corsOrigin, credentials: true });
  app.use(cookieParser(cookieSecret));
  app.useGlobalPipes(new GlobalValidationPipe());
  const port = parseInt(process.env.PORT ?? '3000', 10);
  await app.listen(port);
}
bootstrap();
