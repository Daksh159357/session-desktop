import { readFileSync, unlinkSync, writeFileSync } from 'fs';

const ENCODING = 'utf8';

type ValueType = number | string | boolean | null | object;

export function start(
  name: string,
  targetPath: string,
  options: {
    allowMalformedOnStartup?: boolean;
  } = {}
) {
  let currentPath = targetPath;
  let cachedValue: any = Object.create(null);

  function load() {
    try {
      const text = readFileSync(currentPath, ENCODING);
      cachedValue = JSON.parse(text);
      console.log(`config/get: Successfully read ${name} config file`);

      if (!cachedValue) {
        console.log(`config/get: ${name} config value was falsy, cache is now empty object`);
        cachedValue = Object.create(null);
      }
    } catch (error) {
      if (!options.allowMalformedOnStartup && error.code !== 'ENOENT') {
        throw error;
      }

      console.log(`config/get: Did not find ${name} config file, cache is now empty object`);
      cachedValue = Object.create(null);
    }
  }

  load();

  function get(keyPath: string) {
    return cachedValue[keyPath];
  }

  function set(keyPath: string, value: ValueType) {
    cachedValue[keyPath] = value;
    console.log(`config/set: Saving ${name} config to disk`);
    const text = JSON.stringify(cachedValue, null, '  ');
    writeFileSync(currentPath, text, ENCODING);
    console.log(`config/set: Saved ${name} config to disk`);
  }

  function remove() {
    console.log(`config/remove: Deleting ${name} config from disk`);
    unlinkSync(currentPath);
    cachedValue = Object.create(null);
  }

  function setTargetPath(newPath: string) {
    currentPath = newPath;
    load();
  }

  return {
    set,
    get,
    remove,
    setTargetPath,
  };
}
