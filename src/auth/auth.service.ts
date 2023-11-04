import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { find } from 'rxjs';
@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    try {
      // check email exist
      const checkEmailExist =
        await this.prisma.user.findFirst({
          where: {
            email: dto.email,
          },
        });
      if (checkEmailExist) {
        return {
          status: '422',
          message: 'Email đã tồn tại',
        };
      }

      // genarate the password hash
      const hash = await argon.hash(dto.password);

      // save the new user in the db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      delete user.hash;

      // return the saved user
      return {
        status: 200,
        message: 'Success',
      };
    } catch (error) {
      // process if serve disconect
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
    }
  }

  async signin(dto: AuthDto) {
    try {
      // find user by email
      const user = await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });
      // if user does not exist throw exception
      if (!user) {
        return { status: 422, message: 'Email not exists' };
      }
      // compare password
      const pwMatch = await argon.verify(
        user.hash,
        dto.password,
      );
      // if password incorrect throw exception
      if (!pwMatch) {
        return {
          status: 422,
          message: 'Password does not incorrect',
        };
      }
      // if password correct throw exception
      return { status: 200, message: 'Success' };
    } catch (error) {}
  }
}
