import {
  IsEmail,
  IsNotEmpty,
  IsString,
} from 'class-validator';

class AuthDto {
  @IsEmail()
  @IsNotEmpty()
  
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}

export { AuthDto };
