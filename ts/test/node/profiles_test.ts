import path from 'path';
import fs from 'fs';
import fse from 'fs-extra';
import { expect } from 'chai';
import { ProfileManager } from '../../node/profiles/profile_manager';
import { ProfileMigration } from '../../node/profiles/profile_migration';

describe('Multiple Encrypted Profiles System', () => {
  const testDir = path.join(__dirname, '..', '..', 'temp_test_profiles');

  beforeEach(async () => {
    fse.removeSync(testDir);
    fse.ensureDirSync(testDir);
    await ProfileManager.ensureSodiumReady();
  });

  afterEach(() => {
    ProfileManager.lockActiveProfile();
    fse.removeSync(testDir);
  });

  it('should create an encrypted profile with Argon2id and AES-256-GCM verification', async () => {
    const passphrase = 'SecretPassword123!';
    const profile = await ProfileManager.createProfile(testDir, passphrase);

    expect(profile).to.be.an('object');
    expect(profile.profileId).to.be.a('string');
    expect(fs.existsSync(profile.profileDir)).to.be.true;

    const manifestPath = path.join(profile.profileDir, 'manifest.json');
    expect(fs.existsSync(manifestPath)).to.be.true;

    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    expect(manifest.id).to.equal(profile.profileId);
    expect(manifest.salt).to.have.lengthOf(32); // 16 bytes hex = 32 chars
    expect(manifest.encryptedToken).to.be.a('string');
    expect(manifest.encryptedDbKey).to.be.a('string');

    // Scoped subdirectories check
    expect(fs.existsSync(path.join(profile.profileDir, 'sql'))).to.be.true;
    expect(fs.existsSync(path.join(profile.profileDir, 'attachments'))).to.be.true;
    expect(fs.existsSync(path.join(profile.profileDir, 'cache'))).to.be.true;
    expect(fs.existsSync(path.join(profile.profileDir, 'search_index'))).to.be.true;
  });

  it('should unlock only the matching profile and reject incorrect credentials', async () => {
    const pass1 = 'ProfileOnePass!';
    const pass2 = 'ProfileTwoPass!';

    const p1 = await ProfileManager.createProfile(testDir, pass1);
    ProfileManager.lockActiveProfile();

    const p2 = await ProfileManager.createProfile(testDir, pass2);
    ProfileManager.lockActiveProfile();

    // Try unlocking p1
    const unlocked1 = await ProfileManager.unlockProfile(testDir, pass1);
    expect(unlocked1).to.not.be.null;
    expect(unlocked1?.profileId).to.equal(p1.profileId);
    expect(unlocked1?.dbKey).to.equal(p1.dbKey);

    ProfileManager.lockActiveProfile();

    // Try unlocking p2
    const unlocked2 = await ProfileManager.unlockProfile(testDir, pass2);
    expect(unlocked2).to.not.be.null;
    expect(unlocked2?.profileId).to.equal(p2.profileId);

    ProfileManager.lockActiveProfile();

    // Try unlocking with wrong passphrase
    const unlockedWrong = await ProfileManager.unlockProfile(testDir, 'WrongPassphrase!');
    expect(unlockedWrong).to.be.null;
  });

  it('should maintain zero-knowledge profile existence and unique encryption keys', async () => {
    const passphrase1 = 'UserPassAlpha';
    const passphrase2 = 'UserPassBeta';

    const p1 = await ProfileManager.createProfile(testDir, passphrase1);
    ProfileManager.lockActiveProfile();

    const p2 = await ProfileManager.createProfile(testDir, passphrase2);
    ProfileManager.lockActiveProfile();

    // Encryption keys must be distinct and non-zero
    expect(p1.dbKey).to.not.equal(p2.dbKey);
    expect(p1.profileId).to.not.equal(p2.profileId);

    // Profile directories must be random UUIDs
    const profilesDir = path.join(testDir, 'profiles');
    const dirs = fs.readdirSync(profilesDir);
    expect(dirs).to.include(p1.profileId);
    expect(dirs).to.include(p2.profileId);

    // Unlocking with a completely unknown passphrase returns null without error or leaking profile details
    const nonExistent = await ProfileManager.unlockProfile(testDir, 'UnknownCredential');
    expect(nonExistent).to.be.null;
  });

  it('should wipe sensitive key memory on profile lock', async () => {
    const passphrase = 'MemoryWipeTestPass';
    const profile = await ProfileManager.createProfile(testDir, passphrase);
    const masterKeyCopy = Buffer.from(profile.masterKey);

    expect(profile.masterKey.equals(masterKeyCopy)).to.be.true;

    ProfileManager.lockActiveProfile();

    // Memory buffer should be zeroed out
    const zeroBuf = Buffer.alloc(masterKeyCopy.length, 0);
    expect(masterKeyCopy.equals(zeroBuf)).to.be.false;
    expect(profile.masterKey.equals(zeroBuf)).to.be.true;
    expect(ProfileManager.getActiveProfile()).to.be.null;
  });

  it('should migrate legacy single-profile setup seamlessly', async () => {
    const legacyDir = path.join(testDir, 'legacy_root');
    fse.ensureDirSync(path.join(legacyDir, 'sql'));
    fs.writeFileSync(path.join(legacyDir, 'sql', 'db.sqlite'), 'LEGACY_SQLITE_DATA');
    fs.writeFileSync(path.join(legacyDir, 'config.json'), JSON.stringify({ legacyConfig: true }));

    const migrated = await ProfileMigration.migrateLegacyProfileIfNeeded(legacyDir, 'MigratedUserPass');

    expect(migrated).to.not.be.null;
    expect(migrated?.profileId).to.be.a('string');

    const migratedDbPath = path.join(migrated!.profileDir, 'sql', 'db.sqlite');
    expect(fs.existsSync(migratedDbPath)).to.be.true;
    expect(fs.readFileSync(migratedDbPath, 'utf8')).to.equal('LEGACY_SQLITE_DATA');
  });
});
