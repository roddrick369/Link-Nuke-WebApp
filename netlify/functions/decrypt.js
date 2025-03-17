const { createDecipheriv } = require('crypto');

exports.handler = async (event) => {
    try {
        const { encryptedText } = JSON.parse(event.body);
        
        // Recupera a chave secreta das variáveis de ambiente (Base64)
        const secretKey = Buffer.from(process.env.SECRET_KEY, 'base64');
        
        // Decodifica o texto criptografado (formato: nonce + tag + ciphertext)
        const buffer = Buffer.from(encryptedText, 'base64url');
        const nonce = buffer.subarray(0, 12);
        const tag = buffer.subarray(12, 28);
        const ciphertext = buffer.subarray(28);

        // Decifra usando AES-256-GCM
        const decipher = createDecipheriv('aes-256-gcm', secretKey, nonce);
        decipher.setAuthTag(tag);
        
        const decrypted = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]);

        return {
            statusCode: 200,
            body: JSON.stringify({ 
                success: true, 
                result: decrypted.toString('utf-8') 
            })
        };
    } catch (error) {
        return {
            statusCode: 200,
            body: JSON.stringify({ 
                success: false, 
                error: "Decryption failed. Invalid or tampered link." 
            })
        };
    }
};
