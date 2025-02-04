import * as jwt from 'jsonwebtoken';
import { Injectable } from '@nestjs/common';

@Injectable()
export class JwtUtils {
  private readonly jwtSecret = process.env.JWT_SECRET ?? 'your-secret-key'  ;


  // Generate JWT Token
  generateToken(payload: any): string {

    if (!this.jwtSecret) {
      throw new Error('JWT_SECRET is not defined');
    }

    console.log(this.jwtSecret);

    return jwt.sign(payload, this.jwtSecret, { expiresIn: '1h' });
  }

  // Verify JWT Token
  verifyToken(token: string): any {
    try {
      if (!this.jwtSecret) {
        throw new Error('JWT_SECRET is not defined');
      }
      return jwt.verify(token, this.jwtSecret);
    } catch (e) {
      return null;
    }
  }
}