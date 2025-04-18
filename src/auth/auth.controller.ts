import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserService } from 'src/user/user.service';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly userService: UserService,
    ) {}

    @Post('register')
    async register(@Body() body: { name: string, email: string, password: string }) {
        const { name, email, password } = body;
        const user = await this.userService.createUser(name, email, password);
        return {
            message: 'Usuário criado com sucesso',
            user 
        };
    }

    @Post('login')
    async login(@Body() body: { email: string, password: string }) {
        const { email, password } = body;
        return await this.authService.login(email, password);
    }

    @Post('refresh')
    async refresh(@Body() body: { refreshToken: string }) {
        const { refreshToken } = body;
        return await this.authService.refresh(refreshToken);
    }
}
