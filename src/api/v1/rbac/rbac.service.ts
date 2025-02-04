import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class RbacService {
    constructor(private readonly prisma:PrismaService){}

     // Utility method for consistent response format
        private formatResponse(
        statusCode: number,
        message: string,
        success: boolean,
        data: any = null,
  ) {
    return { status_code: statusCode, message, success, data };
  }

    // --------------------Permission management----------------------- //

    // Get all permissions
  async getPermissions() {

    try{
        // Fetch all permissions
    const permissions = await this.prisma.permission.findMany();

    // Check if permissions were found
    if (permissions.length === 0) {
        // No permissions found
        return this.formatResponse(404, 'No permissions found', true, []);
      }
    
    // Permissions found
    return this.formatResponse(200, 'Permissions found', true, permissions);
    } catch (error){
        // Handle database or server errors
        return this.formatResponse(500, 'Unable to retrieve permissions due to server issues', false, error.message)
    }
  }



    // Create a new permission
  async createPermission(title: string, slug: string) {

    // Check if a permission with the same slug already exists
  const existingPermission = await this.prisma.permission.findUnique({
    where: { slug },
  });
  if (existingPermission) {
      return this.formatResponse(409, 'A permission with this slug already exists', false)
  }

    try{
      // Create the permission
      const newPermission = await this.prisma.permission.create({
      data: { title, slug },
    });
    return this.formatResponse(201,'Permission created successfully',true, newPermission);
    } catch (error){
      return this.formatResponse(500, 'Unable to create permission due to server issues', false, error.message)
    }
  }



    // ---------------------Role management-------------------------- //

    // Get all roles
    async getRoles() {

      try{
        // Fetch all roles
        const roles = await this.prisma.role.findMany();

        // Check if roles were found
        if (roles.length === 0) {
            return this.formatResponse(404, 'No roles found', true, []);
          }
        
          return this.formatResponse(200, 'Roles found', true, roles);
      } catch (error){
        return this.formatResponse(500, 'Unable to retrieve roles due to server issues', false, error.message)
      }
      }


    // Create a new role
    async createRole(title: string) {

      // Check if a role with the same title already exists
      const existingRole =  await this.prisma.role.findFirst({
        where: { title },
      });
      if (existingRole) {
      return this.formatResponse(409, 'A role with this title already exists', false)
  }
        try{
          // Create the role
          const newRole = await this.prisma.role.create({ data: { title } });
          return this.formatResponse(201, 'Role created successfully', true, newRole);
        }catch (error){
          return this.formatResponse(500, 'Unable to create role due to server issues', false, error.message);
        }
      }

// Role to permission management

    // Assign a permission to a role
    async assignPermissionToRole(roleId: string, permissionId: string) {

         // Validate if the role exists
        const role = await this.prisma.role.findUnique({ where: { id: roleId } });
        if (!role) {
          return this.formatResponse(404, 'Role not found', false);
        }

        // Validate if the permission exists
        const permission = await this.prisma.permission.findUnique({ where: { id: permissionId } });
        if (!permission) {
          return this.formatResponse(404, 'Permission not found', false);
        }

        // Check if the permission is already assigned to the role
        const existingRelation = await this.prisma.permissionToRole.findFirst({
          where: { roleId, permissionId },
        });
        if (existingRelation) {
          return this.formatResponse(409, 'Permission already assigned to role', false);
        }
        
        try{
          const assignment = await this.prisma.permissionToRole.create({
            data: { roleId, permissionId },
          });
          return this.formatResponse(201, 'Permission assigned to role successfully', true, assignment);
        } catch(error){
          return this.formatResponse(500, 'Unable to assign permission to role due to server issues', false, error.message);
        }
      }
    
    // Remove a permission from a role
    async unassignPermissionFromRole(roleId: string, permissionId: string) {
      // Check if the relation exists
        const relation = await this.prisma.permissionToRole.findFirst({
          where: { roleId, permissionId },
        });
        if (!relation) return this.formatResponse(404, 'Relation not found', false);

        // Delete the relation
        try{
          await this.prisma.permissionToRole.delete({ where: { id: relation.id } });
          return this.formatResponse(200, 'Permission removed from role successfully', true);
        } catch(error){
          return this.formatResponse(500, 'Unable to remove permission from role due to server issues', false, error.message);
        }

      }

// ---------------------------User to role management--------------------------------- //

    // Assign a role to a user
    async assignRoleToUser(roleId: string, userId: string) {
      // Check if the role exists
        const role = await this.prisma.role.findUnique({ where: { id: roleId } });
        if (!role) return this.formatResponse(404, 'Role not found', false);

        // Check if the user exists
        // const user = await this.prisma.user.findUnique({ where: { id: userId } });
        // if (!user) return this.formatResponse(404, 'User not found', false);

        // Check if the role is already assigned to the user
        const existingRelation = await this.prisma.roleToUser.findFirst({
          where: { roleId, userId },
        });
        if (existingRelation) return this.formatResponse(409, 'Role already assigned to user', false);
        
        // Assign the role to the user
        try{
          const assignment = await this.prisma.roleToUser.create({
            data: { roleId, userId },
          });
          return this.formatResponse(201, 'Role assigned to user successfully', true, assignment);
        } catch(error){
          return this.formatResponse(500, 'Unable to assign role to user due to server issues', false, error.message);
        }
      }
    
    // Remove a role from a user
    async unassignRoleFromUser(roleId: string, userId: string) {

      // Check if the relation exists
        const relation = await this.prisma.roleToUser.findFirst({
          where: { roleId, userId },
        });
        if (!relation) return this.formatResponse(404, 'Relation not found', false);

        // Delete the relation
        try{
          await this.prisma.roleToUser.delete({ where: { id: relation.id } });
          return this.formatResponse(200, 'Role removed from user successfully', true);
        } catch(error){
          return this.formatResponse(500, 'Unable to remove role from user due to server issues', false, error.message);
        }
      }

      // Get all roles assigned to a user
      async getUserRoles(userId: string) {
        return this.prisma.roleToUser.findMany({
          where: { userId },
          include: { role: { include: { permissions: { include: { permission: true } } } } },
        });
      }
}
