import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import fse from 'fs-extra';

// libsodium-wrappers-sumo for Argon2id key derivation
// eslint-disable-next-line @typescript-eslint/no-var-requires
const sodium = require('libsodium-wrappers-sumo');

export interface ProfileMetadata {
  profileId: string;
  profileDir: string;
  dbKey: string;
  masterKey: Buffer;
}

export interface ProfileManifest {
  id: string;
  salt: string; // hex
  iv: string; // hex
  tag: string; // hex
  encryptedToken: string; // hex
  dbKeyIv: string; // hex
  dbKeyTag: string; // hex
  encryptedDbKey: string; // hex
  createdAt: number;
}

const VERIFICATION_TOKEN = 'SESSION_PROFILE_MAGIC_VERIFICATION_HEADER';

let activeProfile: ProfileMetadata | null = null;

export class ProfileManager {
  /**
   * Ensures libsodium is ready for Argon2id KDF operations.
   */
  public static async ensureSodiumReady(): Promise<void> {
    await sodium.ready;
  }

  /**
   * Derive a 32-byte master key using Argon2id with a unique random salt.
   */
  public static deriveMasterKey(passphrase: string, salt: Buffer): Buffer {
    if (!salt || salt.length < 16) {
      throw new Error('Salt must be at least 16 bytes');
    }
    const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE || 2;
    const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE || 67108864;
    const alg = sodium.crypto_pwhash_ALG_ARGON2ID13 || 2;

    const derivedKey = sodium.crypto_pwhash(
      32,
      Buffer.from(passphrase, 'utf8'),
      salt,
      opslimit,
      memlimit,
      alg
    );
    return Buffer.from(derivedKey);
  }

  /**
   * Encrypt plaintext using AES-256-GCM with the derived master key.
   */
  public static encryptAESGCM(
    masterKey: Buffer,
    plaintext: string | Buffer
  ): { ciphertext: Buffer; iv: Buffer; tag: Buffer } {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
    const inputBuf = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;
    const ciphertext = Buffer.concat([cipher.update(inputBuf), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { ciphertext, iv, tag };
  }

  /**
   * Decrypt AES-256-GCM ciphertext using the derived master key.
   * Throws an error if authentication tag verification fails.
   */
  public static decryptAESGCM(
    masterKey: Buffer,
    ciphertext: Buffer,
    iv: Buffer,
    tag: Buffer
  ): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  /**
   * Securely wipe sensitive data (buffers) from memory.
   */
  public static secureWipeMemory(...buffers: (Buffer | null | undefined)[]): void {
    for (const buf of buffers) {
      if (buf && Buffer.isBuffer(buf)) {
        buf.fill(0);
      }
    }
  }

  /**
   * Attempt to unlock an existing profile using the provided passphrase.
   * Uses zero-knowledge lookup across profile manifests without revealing profile existence.
   */
  public static async unlockProfile(
    baseUserDataPath: string,
    passphrase: string
  ): Promise<ProfileMetadata | null> {
    await this.ensureSodiumReady();
    const profilesDir = path.join(baseUserDataPath, 'profiles');

    if (!fs.existsSync(profilesDir)) {
      return null;
    }

    const entries = fs.readdirSync(profilesDir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      const profileDir = path.join(profilesDir, entry.name);
      const manifestPath = path.join(profileDir, 'manifest.json');

      if (!fs.existsSync(manifestPath)) continue;

      try {
        const manifestRaw = fs.readFileSync(manifestPath, 'utf8');
        const manifest: ProfileManifest = JSON.parse(manifestRaw);

        const salt = Buffer.from(manifest.salt, 'hex');
        const masterKey = this.deriveMasterKey(passphrase, salt);

        // Attempt verification token decryption
        const iv = Buffer.from(manifest.iv, 'hex');
        const tag = Buffer.from(manifest.tag, 'hex');
        const encryptedToken = Buffer.from(manifest.encryptedToken, 'hex');

        const decryptedTokenBuf = this.decryptAESGCM(masterKey, encryptedToken, iv, tag);
        const decryptedToken = decryptedTokenBuf.toString('utf8');

        if (decryptedToken === VERIFICATION_TOKEN) {
          // Unlocked successfully! Now decrypt database key
          const dbKeyIv = Buffer.from(manifest.dbKeyIv, 'hex');
          const dbKeyTag = Buffer.from(manifest.dbKeyTag, 'hex');
          const encryptedDbKey = Buffer.from(manifest.encryptedDbKey, 'hex');

          const dbKeyBuf = this.decryptAESGCM(masterKey, encryptedDbKey, dbKeyIv, dbKeyTag);
          const dbKey = dbKeyBuf.toString('utf8');

          const metadata: ProfileMetadata = {
            profileId: manifest.id,
            profileDir,
            dbKey,
            masterKey,
          };

          activeProfile = metadata;
          return metadata;
        } else {
          this.secureWipeMemory(masterKey);
        }
      } catch (e) {
        // Tag verification or decryption failed for this profile manifest (incorrect credential)
        continue;
      }
    }

    return null;
  }

  /**
   * Create a new encrypted profile with an Argon2id key, AES-256-GCM verification, and random UUID.
   */
  public static async createProfile(
    baseUserDataPath: string,
    passphrase: string
  ): Promise<ProfileMetadata> {
    await this.ensureSodiumReady();

    const profileId = crypto.randomUUID();
    const profileDir = path.join(baseUserDataPath, 'profiles', profileId);
    const salt = crypto.randomBytes(16);
    const masterKey = this.deriveMasterKey(passphrase, salt);

    // Generate random 32-byte DB key (hex encoded)
    const dbKey = crypto.randomBytes(32).toString('hex');

    // Encrypt verification token
    const tokenResult = this.encryptAESGCM(masterKey, VERIFICATION_TOKEN);
    // Encrypt DB key
    const dbKeyResult = this.encryptAESGCM(masterKey, dbKey);

    const manifest: ProfileManifest = {
      id: profileId,
      salt: salt.toString('hex'),
      iv: tokenResult.iv.toString('hex'),
      tag: tokenResult.tag.toString('hex'),
      encryptedToken: tokenResult.ciphertext.toString('hex'),
      dbKeyIv: dbKeyResult.iv.toString('hex'),
      dbKeyTag: dbKeyResult.tag.toString('hex'),
      encryptedDbKey: dbKeyResult.ciphertext.toString('hex'),
      createdAt: Date.now(),
    };

    // Ensure directory structure
    fse.ensureDirSync(profileDir);
    fse.ensureDirSync(path.join(profileDir, 'sql'));
    fse.ensureDirSync(path.join(profileDir, 'attachments'));
    fse.ensureDirSync(path.join(profileDir, 'cache'));
    fse.ensureDirSync(path.join(profileDir, 'search_index'));

    // Write manifest
    fs.writeFileSync(path.join(profileDir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');

    // Write initial profile config
    const initialConfig = {
      dbHasPassword: true,
      key: dbKey,
    };
    fs.writeFileSync(path.join(profileDir, 'config.json'), JSON.stringify(initialConfig, null, 2), 'utf8');

    const metadata: ProfileMetadata = {
      profileId,
      profileDir,
      dbKey,
      masterKey,
    };

    activeProfile = metadata;
    return metadata;
  }

  /**
   * Lock the currently active profile, wiping keys and resetting memory.
   */
  public static lockActiveProfile(): void {
    if (activeProfile) {
      this.secureWipeMemory(activeProfile.masterKey);
      activeProfile = null;
    }
  }

  /**
   * Returns the currently active profile metadata if unlocked.
   */
  public static getActiveProfile(): ProfileMetadata | null {
    return activeProfile;
  }
}
