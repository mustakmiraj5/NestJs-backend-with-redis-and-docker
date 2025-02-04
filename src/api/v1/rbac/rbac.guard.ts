import {
    Injectable,
    CanActivate,
    ExecutionContext,
    ForbiddenException,
  } from '@nestjs/common';
  import { Reflector } from '@nestjs/core';
  import { RbacService } from './rbac.service';
  
  @Injectable()
  export class RbacGuard implements CanActivate {
    constructor(
      private readonly reflector: Reflector,
      private readonly rbacService: RbacService,
    ) {}
  
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const requiredPermission = this.reflector.get<string>(
        'permission',
        context.getHandler(),
      );
  
      if (!requiredPermission) return true;
  
      const request = context.switchToHttp().getRequest();
      const userId = request.user?.id;
  
      if (!userId) throw new ForbiddenException('User not authenticated');
  
      const roles = await this.rbacService.getUserRoles(userId);
  
      const hasPermission = roles.some((role) =>
        role.role.permissions.some(
          (perm) => perm.permission.slug === requiredPermission,
        ),
      );
  
      if (!hasPermission) throw new ForbiddenException('Access denied');
      return true;
    }
  }
  