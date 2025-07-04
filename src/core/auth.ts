const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const md5 = require("md5");
const jwt = require('jsonwebtoken');

export interface JWTSpecs {
    secretKey: string,
    expiryTimeMs: any
}

export interface UserProvider {
    getUser(login: string): Promise<BaseUser>
    putUser(user: any): Promise<any>
    userSecretPath?: string
    userPasswordPath?: string
    // deprecated, use getUserPostAuthenticate() instead
    getSafeUser?(user: any): Promise<BaseUser> // when provided will be called to clear sensitive data from user object before encoding it into JWT token
    // when provided will be called to eventually clear sensitive data from user object before encoding it into JWT token or to do some other operation
    // this method (when provided) is called to generate the actual user data that will be encoded into token
    getUserPostAuthenticate?(user: any): Promise<BaseUser> 
}
export interface ImpersonateProvider {
    canImpersonate(user:any, target:string): Promise<any>
    impersonateOrg(user: any, target: string): Promise<any>
}

export interface BaseUser {
    blocked?: boolean
    [key: string]: any
}

/**
 * When mfaToken is provided
 */
export const authenticate = async (login:string, password:string, mfaToken:string, impersonateEntity:string, userProvider:UserProvider, impersonateProvider:any, jwtSpecs: JWTSpecs) => {
    let user = await userProvider.getUser(login);

    const mfaInfo = userProvider.userSecretPath?user[userProvider.userSecretPath]:user.mfa;
    const userPassword = userProvider.userPasswordPath?user[userProvider.userPasswordPath]:user.password;


    if(mfaInfo?.enabled){    
        // console.log(`Validating ${mfaToken} vs mfa info ${JSON.stringify(mfaInfo)} `)            
        // Validate the token against the user's saved secret
        const validated = speakeasy.totp.verify({
            secret: mfaInfo?.secret?.actual,
            encoding: 'base32',
            token: mfaToken,
            window: 1, // Adjust window size if tokens have a margin of error
        });
        if(!validated) throw new Error(`Failed authentication attempt ${login} (MFA Enabled)`)
    }    

    if(user.blocked) throw new Error(`Failed authentication attempt ${login} (Blocked)`);

    if(md5(password||'') == userPassword){    
        // check if impersonate mode - this is not yet implemented fully just copy pasta from GRM project
        const target = impersonateEntity; // either target user login or @organizationId
        const originalUser = user;

        if(target){
            
            // impersonate flow
            let mayImpersonate = false;

            // check mode - when starts with @ we try to impersonate only to organization, otherwise we impersonate to another user
            if(target.startsWith("@")){
                // only organization impersonation
                // check requesting user has global admin
                // mayImpersonate = mayImpersonate || user.roles.map(role=>role.toUpperCase()).includes(UserManager.CONST.ROLES.GRM_ADMIN);
                mayImpersonate = mayImpersonate || await impersonateProvider.canImpersonate(user, target);
                // mayImpersonate = true;
                // todo check org exists                    

                if(!mayImpersonate){
                    throw new Error(`Failed impersonate attempt. From: ${originalUser.id} into ${target}`)                    
                } 

                // switch original user organization_id
                await impersonateProvider.impersonateOrg(user, target);
                // await userManager.impersonateOrganization(user, target.substring(1).trim());
                // const organization = await commons.dbApi.adminApi.organization();
                // user.organization_id = parseInt(target.substring(1).trim()); // skip "@" at the beginning
                // user.organization = organization;
            }
            else{
                // full user impersonation
                // load target user
                const targetUser = await userProvider.getUser(target); 
                
                // check requesting user has target user's org admin role                
                // mayImpersonate = mayImpersonate || (user.organization_id == targetUser.organization_id && user.roles.map(role=>role.toUpperCase()).includes(UserManager.CONST.ROLES.ORG_ADMIN))
                // check requesting user has global admin
                // mayImpersonate = mayImpersonate || user.roles.map(role=>role.toUpperCase()).includes(UserManager.CONST.ROLES.GRM_ADMIN);
                mayImpersonate = mayImpersonate || await impersonateProvider.canImpersonate(user, target);

                if(!mayImpersonate){
                    throw new Error(`Failed impersonate attempt. From: ${originalUser.id} into ${target}`);                        
                }
                
                // allowed to impersonate so "switch" user to target user
                user = targetUser;
            }
                            
            console.info(`Impersonate success. From: ${originalUser.login} into ${target}`);
        }            

        // let jwtSecretKey = process.env.JWT_SECRET_KEY;
        let jwtSecretKey = jwtSpecs.secretKey

        let clearedUser = userProvider.getSafeUser? await userProvider.getSafeUser(user) : user;
        clearedUser = userProvider.getUserPostAuthenticate? await userProvider.getUserPostAuthenticate(clearedUser) : clearedUser;        
        
        let data = {
            time: Date.now(),                
            user: clearedUser
        }                    
        // const token = jwt.sign(data, jwtSecretKey, {expiresIn: process.env.JWT_EXPIRY_TIME});
        const token = jwt.sign(data, jwtSecretKey, {expiresIn: jwtSpecs.expiryTimeMs});
        console.log(`Successful login: ${user.id}`);
        return token;
    }else{
        throw new Error(`Failed authentication attempt ${login}`)
    }    
}
/**
 * Will prepare user for MFA activation. Next step is to call verify with token generated in MFA app by the user.
 */
export const mfaRegister = async (appName:string, login:string, userProvider: UserProvider) => {
    return new Promise(async (resolve, _reject)=>{
        let user = await userProvider.getUser(login);  
        let mfaInfo = userProvider.userSecretPath?user[userProvider.userSecretPath]:user.mfa;            
        // console.log(`mfaInfo = ${JSON.stringify(mfaInfo)}`)
        const secret = speakeasy.generateSecret({
            name: `${appName}: ${login}`, 
        });
    
        if(!mfaInfo){
            mfaInfo = {
                secret: {
                    temp: undefined,
                    actual: undefined                
                },
                enabled: false
            }
            // console.log(`mfaInfo2 = ${JSON.stringify(mfaInfo)}`)
            const propName = userProvider.userSecretPath?userProvider.userSecretPath:"mfa";
            user[propName] = mfaInfo
            // console.log(`user = ${JSON.stringify(user)}`)
        } 
        mfaInfo.secret.temp = secret.base32
        mfaInfo.secret.actual = undefined
        // console.log(`user2 = ${JSON.stringify(user)}`)
    
        await userProvider.putUser(user);
    
        qrcode.toDataURL(secret.otpauth_url, (err:any, data:any)=>{
            if (err) {
                throw new Error('Error generating QR code');            
            } else {
                // Send the QR code URL and the secret
                resolve({ 
                    qr_code: data, 
                    secret: secret.base32 
                });
            }
        })
    })    
}

/**
 * Will return true and fully initialize MFA for user when token verification was ok. Otherwise will result false;
 */
export const mfaVerify = async (login:string, mfaToken:string, userProvider:UserProvider) => {
    const token = mfaToken;

    // load user
    let user = await userProvider.getUser(login);
    const mfaInfo = userProvider.userSecretPath?user[userProvider.userSecretPath]:user.mfa;        

    // Verify the token using the saved secret
    const verified = speakeasy.totp.verify({
        secret: mfaInfo?.secret?.temp,
        encoding: 'base32',
        token,
    });

    if (verified) {
        mfaInfo.secret.actual = mfaInfo?.secret?.temp
        mfaInfo.enabled = true;
        await userProvider.putUser(user);                                        
        return true;
    }else{
        console.log(`Failed mfa verification for ${login}`);        
        return false;
    }       
}

export const mfaEnabled = async (login:string, userProvider:UserProvider) => {
    let user = await userProvider.getUser(login);
    const mfaInfo = userProvider.userSecretPath?user[userProvider.userSecretPath]:user.mfa;    
    return mfaInfo?.enabled || false;
}
