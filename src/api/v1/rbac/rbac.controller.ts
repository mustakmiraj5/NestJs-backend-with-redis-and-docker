import { BadRequestException, Body, Controller, Delete, Get, Param, Post } from '@nestjs/common';
import { RbacService } from './rbac.service';

@Controller('rbac')
export class RbacController {
    constructor(private readonly rbacService: RbacService) {}


    // --------------------Permission management----------------------- //

    // Get all permissions
    @Get('permissions')
    async getPermissions() {
    return this.rbacService.getPermissions();
  }

  // Create a new permission
  @Post('permission')
  async createPermission(@Body() body: { title: string; slug: string }) {
    const { title, slug } = body;
    if (!title || !slug) throw new BadRequestException('Title and slug are required');
    return this.rbacService.createPermission(title, slug);
  }

  // ---------------------Role management-------------------------- //

  // Get all roles
  @Get('roles')
    async getRoles() {
    return this.rbacService.getRoles();
  }

  // Create a new role
  @Post('role')
  async createRole(@Body() body: { title: string }) {
    const { title } = body;
    if (!title) throw new BadRequestException('Title is required');
    return this.rbacService.createRole(title);
  }
  
  //----------------------- Role to permission management----------------------------- //

  // Assign permission to role
  @Post('role/:roleId/permission/:permissionId')
  async assignPermissionToRole(
    @Param('roleId') roleId: string,
    @Param('permissionId') permissionId: string,
  ) {
    return this.rbacService.assignPermissionToRole(roleId, permissionId);
  }

  // Remove permission from role
  @Delete('role/:roleId/permission/:permissionId')
  async unassignPermissionFromRole(
    @Param('roleId') roleId: string,
    @Param('permissionId') permissionId: string,
  ) {
    return this.rbacService.unassignPermissionFromRole(roleId, permissionId);
  }

  // --------------------User to role management---------------------------------- //

  // Assign role to user
  @Post('role/:roleId/user/:userId')
  async assignRoleToUser(
    @Param('roleId') roleId: string,
    @Param('userId') userId: string,
  ) {
    return this.rbacService.assignRoleToUser(roleId, userId);
  }

  // Remove role from user
  @Delete('role/:roleId/user/:userId')
  async unassignRoleFromUser(
    @Param('roleId') roleId: string,
    @Param('userId') userId: string,
  ) {
    return this.rbacService.unassignRoleFromUser(roleId, userId);
  }
}
