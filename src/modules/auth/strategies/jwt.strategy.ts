import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import type { AppConfig } from '../../../config/configuration';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private config: ConfigService) {
    // Try direct env access first to debug
    const secretFromEnv = process.env.JWT_ACCESS_SECRET;
  const secret = (config.get('app.jwtAccessSecret') as string) || secretFromEnv;
    
    console.log('JWT Debug - secret from env:', secretFromEnv);
  console.log('JWT Debug - secret from config:', config.get('app.jwtAccessSecret'));
    console.log('JWT Debug - final secret:', secret);
    
    if (!secret) {
      throw new Error('JWT_ACCESS_SECRET is not configured');
    }
    
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          // Extract from Authorization header only (more secure)
          // Cookies are used only for refresh tokens
          return ExtractJwt.fromAuthHeaderAsBearerToken()(request);
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: secret,
    });
  }

  async validate(payload: any) {
    // Validate token payload structure
    if (!payload.sub || !payload.email) {
      return null;
    }

    return { 
      userId: payload.sub, 
      email: payload.email,
      iat: payload.iat,
      exp: payload.exp,
    };
  }
}
