import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-google-oauth20';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor() {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
      scope: ['profile', 'email'],
    });
  }

  validate(_accessToken: string, _refreshToken: string, profile: Profile) {
    const email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : undefined;
    const firstName = profile.name?.givenName || '';
    const lastName = profile.name?.familyName || '';
    const picture = profile.photos && profile.photos.length > 0 ? profile.photos[0].value : undefined;
    return {
      provider: 'google',
      googleId: profile.id,
      email,
      firstName,
      lastName,
      picture,
    };
  }
}
