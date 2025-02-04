import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtValidationService {
  private publicKey: string;

  constructor(private readonly jwtService: JwtService) {
    this.publicKey = process.env.JWT_PUBLIC_KEY ?? '';
  }

  /**
   * Validate a JWT token.
   */
  async validateToken(token: string): Promise<any> {
    try {
      const payload = await this.jwtService.verifyAsync(token, { publicKey: this.publicKey });
      return payload;
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token.');
    }
  }
}
