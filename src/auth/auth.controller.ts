import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SigninDtop, SignupDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto:SignupDto,@Req() req, @Res() res){
    return this.authService.signup(dto, req, res)
  }

  @Post('signin')
  signin(@Body() dto:SigninDtop, @Req() req, @Res() res){
    return this.authService.signin(dto, req, res)
  }

  @Get('signout')
  signout(@Req() req, @Res() res){
    return this.authService.signout(req, res)
  }

  @Get('refreshToken')
  refreshToken(@Req() req, @Res() res) {
    return this.authService.refreshToken(req, res)
  }
}
