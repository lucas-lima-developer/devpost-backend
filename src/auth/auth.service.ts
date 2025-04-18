import { Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
    ) {}

    async login(email: string, password: string) {
        const user = await this.userService.findUserByEmail(email);
        if (!user) {
            throw new Error('Nenhum usuário encontrado com esse email');
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            throw new Error('Email ou senha inválidos');
        }

        const payload = { email: user.email, sub: user.id };
        const accessToken = this.jwtService.sign(payload);

        const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });

        return {
            accessToken,
            refreshToken,
        };
    }

    async refresh(refreshToken: string) {
        const payload = this.jwtService.verify(refreshToken);
        const user = await this.userService.findUserByEmail(payload.email);
        if (!user) {
            throw new Error('Usuário não encontrado');
        }

        const newAcessToken = this.jwtService.sign({ email: user.email, sub: user.id });

        return { acessToken: newAcessToken };
    }
}
