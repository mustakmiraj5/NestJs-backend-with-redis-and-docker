import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Observable } from "rxjs";
import { JwtValidationService } from "./jwt-validation.service";

@Injectable()
export class JwtAuthGuard implements CanActivate{
    constructor(private readonly jwtValidationService: JwtValidationService){}

    async canActivate(context: ExecutionContext): Promise<boolean>  {
        const request = context.switchToHttp().getRequest();
        const token = request.headers['authorization']?.split(' ')[1];
        // console.log(token);

        if (!token) {
            throw new UnauthorizedException('Token not found');
          }
          try {
            const payload = await this.jwtValidationService.validateToken(token);
            
            if (!payload || !payload.userId) {
              throw new UnauthorizedException('Invalid token payload.');
            }
            
            request.user = payload; // Attach user info to the request
            return true;
          } catch (error) {
            throw new UnauthorizedException('Invalid or expired token!');
          }
    }
}