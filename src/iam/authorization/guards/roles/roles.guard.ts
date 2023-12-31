import { ActiveUserData } from 'src/iam/interface/active-user-data.interface';
import { REQUEST_USER_KEY } from './../../../iam.constants';
import { Role } from './../../../../users/enums/role.enums';
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { ROLES_KEY } from '../../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const contextRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!contextRoles) return true;
    const user: ActiveUserData = context.switchToHttp().getRequest()[
      REQUEST_USER_KEY
    ];
    if (!user?.role) {
      throw new ForbiddenException('Role is undefined'); // or throw new ForbiddenException();
    }

    return contextRoles.some((role) => user.role === role);
  }
}
