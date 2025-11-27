package co.edu.javeriana.prestamos.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private Integer id_usuario;
    private String token;
    
<<<<<<< HEAD
=======
>>>>>>> d982c93ac0ddc3efdbae5e8fd34c45a4313a607f
    private String refreshToken; 
    private String mensaje;
    private UserInfo usuario_info;
    private String[] permisos;
}
