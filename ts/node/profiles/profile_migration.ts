import fs from 'fs';
import path from 'path';
import fse from 'fs-extra';
import { ProfileManager, ProfileMetadata } from './profile_manager';

export class ProfileMigration {
  /**
   * Checks if legacy single-profile data exists at the root user data path
   * and migrates it into an encrypted profile directory if found.
   */
  public static async migrateLegacyProfileIfNeeded(
    baseUserDataPath: string,
    passphrase: string
  ): Promise<ProfileMetadata | null> {
    const legacyDbPath = path.join(baseUserDataPath, 'sql', 'db.sqlite');
    const profilesDir = path.join(baseUserDataPath, 'profiles');

    // If no legacy database exists or profiles directory already exists with entries, skip legacy migration
    if (!fs.existsSync(legacyDbPath)) {
      return null;
    }

    if (fs.existsSync(profilesDir)) {
      const existingProfiles = fs.readdirSync(profilesDir);
      if (existingProfiles.length > 0) {
        return null;
      }
    }

    console.log('Legacy single-profile data detected. Migrating to encrypted multi-profile architecture...');

    // Create a new encrypted profile container
    const profile = await ProfileManager.createProfile(baseUserDataPath, passphrase);

    // Copy existing directories and config files into the new profile folder
    const itemsToMigrate = ['sql', 'attachments', 'cache', 'search_index', 'config.json', 'ephemeral.json'];

    for (const item of itemsToMigrate) {
      const srcPath = path.join(baseUserDataPath, item);
      const destPath = path.join(profile.profileDir, item);

      if (fs.existsSync(srcPath)) {
        try {
          if (fs.lstatSync(srcPath).isDirectory()) {
            fse.copySync(srcPath, destPath, { overwrite: true });
          } else {
            fse.copySync(srcPath, destPath, { overwrite: true });
          }
        } catch (e) {
          console.warn(`Failed to copy legacy item ${item}:`, e);
        }
      }
    }

    console.log(`Legacy profile successfully migrated to profile ID: ${profile.profileId}`);
    return profile;
  }
}
