import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './api/v1/auth/auth.module';
import { RbacModule } from './api/v1/rbac/rbac.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PrismaModule } from 'prisma/prisma.module';
import { JwtValidationModule } from './api/v1/jwt-validation/jwt-validation.module';
import * as redisStore from 'cache-manager-redis-store';
import { CaptchaModule } from './api/v1/captcha/captcha.module';
import { ThrottlerModule } from '@nestjs/throttler';

@Module({
  imports: [JwtValidationModule, PrismaModule, AuthModule, RbacModule, ConfigModule.forRoot(), CaptchaModule,],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
