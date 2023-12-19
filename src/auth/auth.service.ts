import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { SigninDtop, SignupDto } from './dto/auth.dto';
import { PrismaService } from 'prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  async signup(dto: SignupDto, req: Request, res: Response) {
    try {
      const { name, email, password } = dto;

      const userExists = await this.checkUserExists(email);
      if (userExists) {
        throw new BadRequestException('User with this email already exists');
      }

      const hashedPassword = await this.hashPassword(password);
      const newUser = await this.prisma.user.create({
        data: {
          name,
          email,
          hashedPassword,
        },
      });

      this.logger.log(`Signup successful for email: ${newUser.email}`);
      return res.json({message: 'Registered sucessfully'})
    } catch (error: any) {
      this.logger.error(`Error occurred during signup: ${error.message}`);
      throw error;
    }
  }

  async signin(dto: SigninDtop, req: Request, res: Response) {
    try {
      const { email, password } = dto;

      this.logger.log(`Signin attempt for email: ${email}`);
      const userExists = await this.checkUserExists(email);

      if (!userExists) {
        throw new BadRequestException('User not found');
      }

      const passwordMatched = await this.comparePasswords({
        password,
        hash: userExists.hashedPassword,
      });

      if (!passwordMatched) {
        throw new BadRequestException('Invalid Password');
      }

      const accessToken = await this.signToken(
        { id: userExists.id, name: userExists.name, email: userExists.email },
        process.env.ACCESS_TOKEN_SECRET,
        6000,
      );

      const refreshToken = await this.signToken(
        { id: userExists.id },
        process.env.REFRESH_TOKEN_SECRET,
        86400,
      );

      this.logger.log(`Successful signin for email: ${email}`);
      res.cookie('refreshToken', refreshToken, { httpOnly: true });
      this.logger.log(`Refresh token sent in a secure cookie, will expire in 24`);
      this.logger.log(`Access token sent in response body`);
      return res.json({ token: accessToken });
    } catch (error: any) {
      this.logger.error(`Error occurred during signin: ${error.message}`);
      throw error;
    }
  }

  async signout(req: Request, res: Response) {
    res.clearCookie('refreshToken', { httpOnly: true, path: '/' });
    this.logger.log('Refresh token invalidated sucessfully');
    return res.json({ message: 'Logged out sucesfully' });
  }

  async refreshToken(req: Request, res: Response) {
    try {
      const refreshToken = req.cookies['refreshToken'];
  
      if (!refreshToken) {
        throw new UnauthorizedException('Refresh token not found');
      }
  
      const decodedToken = await this.jwt.verifyAsync(refreshToken, {
        secret: process.env.REFRESH_TOKEN_SECRET,
      });
  
      const expirationTime = decodedToken.exp;
      const currentTime = Math.floor(Date.now() / 1000);
      const isRefreshTokenExpired = expirationTime < currentTime;
  
      if (isRefreshTokenExpired) {
        res.clearCookie('refreshToken', { httpOnly: true, path: '/' });
        this.logger.log("Refresh token expired")
        throw new UnauthorizedException('Refresh token expired');
      }
  
      const userId = decodedToken.id;
      const userExists = await this.prisma.user.findUnique({
        where: { id: userId },
      });
  
      if (!userExists) {
        throw new UnauthorizedException('User not found');
      }
  
      const accessToken = await this.signToken(
        { id: userExists.id, name: userExists.name, email: userExists.email },
        process.env.ACCESS_TOKEN_SECRET,
        6000,
      );
  
      this.logger.log(`New access token sent in response body`);
      return res.json({ token: accessToken });
    } catch (error) {
      throw new UnauthorizedException('Error during token refresh');
    }
  }
  
  async hashPassword(password: string) {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
  }

  async checkUserExists(email: string) {
    return await this.prisma.user.findUnique({ where: { email } });
  }

  async comparePasswords(args: { password: string; hash: string }) {
    return await bcrypt.compare(args.password, args.hash);
  }

  async signToken(
    args: { id: string; name?: string; email?: string },
    secret: string,
    expiresIn?: number,
  ) {
    const payload = args;
    return this.jwt.signAsync(payload, { secret, expiresIn });
  }
}
