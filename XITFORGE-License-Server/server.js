const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');
const { registerOptionsRoutes } = require('./options-routes');
const { registerFreeKeyRoutes, licenseDurationSeconds } = require('./free-key-routes');

const app = express();

const PORT = Number(process.env.PORT || 3000);

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || '';

const ADMIN_TOKEN_SECRET =
  process.env.ADMIN_TOKEN_SECRET || '';

const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL ||
  `http://localhost:${PORT}`;

const DATABASE_URL =
  process.env.DATABASE_URL || '';

if (!DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is not configured.');
  process.exit(1);
}

if (
  !ADMIN_PASSWORD ||
  ADMIN_PASSWORD === 'change-this-password'
) {
  console.warn(
    'WARNING: Set a strong ADMIN_PASSWORD in the environment before public deployment.'
  );
}

if (
  !ADMIN_TOKEN_SECRET ||
  ADMIN_TOKEN_SECRET.length < 32
) {
  console.warn(
    'WARNING: Set ADMIN_TOKEN_SECRET to a random secret of at least 32 characters.'
  );
}

/*
 * ---------------------------------------------------------
 * POSTGRESQL
 * ---------------------------------------------------------
 */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

/*
 * ---------------------------------------------------------
 * DATABASE INITIALIZATION
 * ---------------------------------------------------------
 */

async function initializeDatabase() {

  const client = await pool.connect();

  try {

    /*
     * LICENCIAS
     */

    await client.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        id BIGSERIAL PRIMARY KEY,
        key_hash TEXT NOT NULL UNIQUE,
        key_prefix TEXT NOT NULL,
        key_last4 TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'new',
        expires_at TIMESTAMPTZ NULL,
        duration_days INTEGER NULL,
        first_used_at TIMESTAMPTZ NULL,
        device_limit INTEGER NOT NULL DEFAULT 1,
        note TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
      );
    `);

    /*
     * MIGRACIÓN V2
     * Conserva todas las keys existentes.
     */

    await client.query(`
      ALTER TABLE licenses
      ADD COLUMN IF NOT EXISTS note TEXT NOT NULL DEFAULT '';

      ALTER TABLE licenses
      ADD COLUMN IF NOT EXISTS duration_days INTEGER NULL;

      ALTER TABLE licenses
      ADD COLUMN IF NOT EXISTS first_used_at TIMESTAMPTZ NULL;

      ALTER TABLE licenses
      ADD COLUMN IF NOT EXISTS duration_seconds BIGINT NULL;
    `);

    /*
     * ACTIVACIONES
     */

    await client.query(`
      CREATE TABLE IF NOT EXISTS activations (
        id BIGSERIAL PRIMARY KEY,
        license_id BIGINT NOT NULL
          REFERENCES licenses(id)
          ON DELETE CASCADE,
        device_hash TEXT NOT NULL,
        activated_at TIMESTAMPTZ NOT NULL,
        last_seen_at TIMESTAMPTZ NOT NULL,
        UNIQUE(license_id, device_hash)
      );
    `);

    /*
     * CONTROL DE VERSIÓN DE LA IPA
     *
     * Solo existe una fila (id = 1).
     * Desde el panel se puede cambiar la última versión,
     * la versión mínima permitida y el enlace de descarga.
     */

    await client.query(`
      CREATE TABLE IF NOT EXISTS app_version_config (
        id SMALLINT PRIMARY KEY,
        latest_version TEXT NOT NULL,
        minimum_version TEXT NOT NULL,
        force_update BOOLEAN NOT NULL DEFAULT TRUE,
        download_url TEXT NOT NULL DEFAULT '',
        update_message TEXT NOT NULL DEFAULT
          'Esta versión de XITFORGE ya no está disponible. Descarga la nueva versión para continuar.',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT app_version_single_row CHECK (id = 1)
      );
    `);

    await client.query(
      `
        INSERT INTO app_version_config (
          id,
          latest_version,
          minimum_version,
          force_update,
          download_url,
          update_message,
          updated_at
        )
        VALUES (
          1,
          '1.0.0',
          '1.0.0',
          TRUE,
          '',
          'Esta versión de XITFORGE ya no está disponible. Descarga la nueva versión para continuar.',
          NOW()
        )
        ON CONFLICT (id) DO NOTHING;
      `
    );

    /*
     * INDICES DE LICENCIAS
     */

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_licenses_key_hash
      ON licenses(key_hash);
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_activations_license
      ON activations(license_id);
    `);

    console.log('PostgreSQL license database initialized.');

  } finally {

    client.release();
  }
}

/*
 * ---------------------------------------------------------
 * EXPRESS
 * ---------------------------------------------------------
 */

app.use(
  express.json({
    limit: '32kb'
  })
);

app.use(
  express.urlencoded({
    extended: false
  })
);

/*
 * ---------------------------------------------------------
 * HELPERS
 * ---------------------------------------------------------
 */

function nowIso() {
  return new Date().toISOString();
}

function normalizeKey(value) {

  return String(value || '')
    .trim()
    .toUpperCase();
}

function isValidKeyFormat(key) {

  return /^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3}$/
    .test(key);
}

function hashValue(value) {

  return crypto
    .createHash('sha256')
    .update(String(value), 'utf8')
    .digest('hex');
}

function generateKey() {

  const alphabet =
    'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  const chunk = () => {

    let out = '';

    for (
      let i = 0;
      i < 4;
      i++
    ) {

      out += alphabet[
        crypto.randomInt(
          0,
          alphabet.length
        )
      ];
    }

    return out;
  };

  return [
    chunk(),
    chunk(),
    chunk(),
    chunk()
  ].join('-');
}

function isExpired(expiresAt) {

  return Boolean(
    expiresAt &&
    Date.now() >=
      new Date(expiresAt).getTime()
  );
}


/*
 * ---------------------------------------------------------
 * APP VERSION HELPERS
 * ---------------------------------------------------------
 *
 * XITFORGE usa versiones simples:
 *
 *   1.0.0
 *   1.0.1
 *   1.2.0
 *   2.0.0
 *
 * Se comparan numéricamente, no como texto.
 * ---------------------------------------------------------
 */

function parseAppVersion(value) {

  const version =
    String(value || '')
      .trim();

  if (
    !/^\d+\.\d+\.\d+$/
      .test(version)
  ) {
    return null;
  }

  const parts =
    version
      .split('.')
      .map(Number);

  if (
    parts.some(
      part =>
        !Number.isSafeInteger(part) ||
        part < 0 ||
        part > 999999
    )
  ) {
    return null;
  }

  return {
    version,
    parts
  };
}

function compareAppVersions(
  left,
  right
) {

  const a =
    parseAppVersion(left);

  const b =
    parseAppVersion(right);

  if (!a || !b) {
    return null;
  }

  for (
    let i = 0;
    i < 3;
    i++
  ) {

    if (
      a.parts[i] <
      b.parts[i]
    ) {
      return -1;
    }

    if (
      a.parts[i] >
      b.parts[i]
    ) {
      return 1;
    }
  }

  return 0;
}

function normalizeDownloadUrl(
  value
) {

  const url =
    String(value || '')
      .trim();

  if (!url) {
    return '';
  }

  if (url.length > 2048) {
    return null;
  }

  try {

    const parsed =
      new URL(url);

    if (
      parsed.protocol !== 'https:' &&
      parsed.protocol !== 'http:'
    ) {
      return null;
    }

    return parsed.toString();

  } catch {

    return null;
  }
}

/*
 * ---------------------------------------------------------
 * ADMIN TOKEN
 * ---------------------------------------------------------
 */

function signAdminToken(payload) {

  const body =
    Buffer
      .from(
        JSON.stringify(payload),
        'utf8'
      )
      .toString('base64url');

  const sig =
    crypto
      .createHmac(
        'sha256',
        ADMIN_TOKEN_SECRET
      )
      .update(body)
      .digest('base64url');

  return `${body}.${sig}`;
}

function verifyAdminToken(token) {

  if (
    !token ||
    !ADMIN_TOKEN_SECRET
  ) {
    return false;
  }

  const parts =
    String(token).split('.');

  if (parts.length !== 2) {
    return false;
  }

  const [
    body,
    sig
  ] = parts;

  const expected =
    crypto
      .createHmac(
        'sha256',
        ADMIN_TOKEN_SECRET
      )
      .update(body)
      .digest('base64url');

  if (
    sig.length !==
    expected.length
  ) {
    return false;
  }

  try {

    if (
      !crypto.timingSafeEqual(
        Buffer.from(sig),
        Buffer.from(expected)
      )
    ) {
      return false;
    }

  } catch {

    return false;
  }

  try {

    const payload =
      JSON.parse(
        Buffer
          .from(body, 'base64url')
          .toString('utf8')
      );

    if (
      payload.role !== 'admin'
    ) {
      return false;
    }

    if (
      typeof payload.exp !==
      'number'
    ) {
      return false;
    }

    if (
      Date.now() >
      payload.exp
    ) {
      return false;
    }

    return true;

  } catch {

    return false;
  }
}

function requireAdmin(
  req,
  res,
  next
) {

  const header =
    String(
      req.get('authorization') ||
      ''
    );

  const token =
    header.startsWith('Bearer ')
      ? header.slice(7)
      : '';

  if (!verifyAdminToken(token)) {

    return res
      .status(401)
      .json({
        ok: false,
        error: 'Unauthorized'
      });
  }

  next();
}

/*
 * ---------------------------------------------------------
 * RATE LIMIT
 * ---------------------------------------------------------
 */

const rateBuckets =
  new Map();

function rateLimit({
  windowMs,
  max
}) {

  return (
    req,
    res,
    next
  ) => {

    const ip =
      req.ip ||
      req.socket.remoteAddress ||
      'unknown';

    const routeKey =
      `${req.path}:${ip}`;

    const now =
      Date.now();

    const entry =
      rateBuckets.get(routeKey);

    if (
      !entry ||
      now - entry.startedAt >
        windowMs
    ) {

      rateBuckets.set(
        routeKey,
        {
          startedAt: now,
          count: 1
        }
      );

      return next();
    }

    entry.count += 1;

    if (
      entry.count > max
    ) {

      return res
        .status(429)
        .json({
          ok: false,
          error:
            'Too many requests. Try again later.'
        });
    }

    next();
  };
}

/*
 * ---------------------------------------------------------
 * LICENSE QUERIES
 * ---------------------------------------------------------
 */

async function getLicenseByHash(
  keyHash
) {

  const result =
    await pool.query(
      `
        SELECT
          id,
          key_prefix,
          key_last4,
          status,
          expires_at,
          duration_days,
          duration_seconds,
          first_used_at,
          device_limit,
          note,
          created_at,
          updated_at
        FROM licenses
        WHERE key_hash = $1
        LIMIT 1
      `,
      [keyHash]
    );

  return result.rows[0] || null;
}

async function activateLicenseOnFirstUse(
  license
) {

  if (!license) {
    return license;
  }

  const durationSeconds = licenseDurationSeconds(license);

  const mustStart =
    !license.expires_at &&
    !license.first_used_at &&
    durationSeconds > 0 &&
    (
      license.status === 'new' ||
      license.status === 'active'
    );

  if (!mustStart) {
    return license;
  }

  const timestamp =
    nowIso();

  const expiresAt =
    new Date(
      Date.now() +
      durationSeconds * 1000
    ).toISOString();

  /*
   * Inicio atómico del contador.
   * Solo la primera validación puede establecer estas fechas.
   */
  const activated =
    await pool.query(
      `
        UPDATE licenses
        SET
          status = 'active',
          first_used_at = $1,
          expires_at = $2,
          updated_at = $1
        WHERE id = $3
          AND expires_at IS NULL
          AND first_used_at IS NULL
          AND (duration_days IS NOT NULL OR duration_seconds IS NOT NULL)
        RETURNING
          id,
          key_prefix,
          key_last4,
          status,
          expires_at,
          duration_days,
          duration_seconds,
          first_used_at,
          device_limit,
          note,
          created_at,
          updated_at
      `,
      [
        timestamp,
        expiresAt,
        license.id
      ]
    );

  if (activated.rows.length > 0) {
    return activated.rows[0];
  }

  const refreshed =
    await pool.query(
      `
        SELECT
          id,
          key_prefix,
          key_last4,
          status,
          expires_at,
          duration_days,
          duration_seconds,
          first_used_at,
          device_limit,
          note,
          created_at,
          updated_at
        FROM licenses
        WHERE id = $1
        LIMIT 1
      `,
      [license.id]
    );

  return refreshed.rows[0] || license;
}


async function getActivationCount(
  licenseId
) {

  const result =
    await pool.query(
      `
        SELECT COUNT(*)::int AS count
        FROM activations
        WHERE license_id = $1
      `,
      [licenseId]
    );

  return Number(
    result.rows[0]?.count || 0
  );
}

/*
 * ---------------------------------------------------------
 * HEALTH
 * ---------------------------------------------------------
 */

app.get(
  '/api/health',
  async (req, res) => {

    try {

      await pool.query('SELECT 1');

      res.json({
        ok: true,
        service:
          'XITFORGE License API',
        database:
          'postgresql',
        time:
          nowIso()
      });

    } catch (error) {

      console.error(
        'Health check failed:',
        error
      );

      res
        .status(503)
        .json({
          ok: false,
          error:
            'Database unavailable'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * APP VERSION
 * ---------------------------------------------------------
 *
 * Endpoint público que consulta la IPA:
 *
 *   GET /api/app/version
 *
 * Opcionalmente puede mandar:
 *
 *   GET /api/app/version?current=1.0.0
 *
 * y el servidor devuelve también:
 *
 *   updateAvailable
 *   blocked
 *
 * La configuración solo se cambia desde el panel admin.
 * ---------------------------------------------------------
 */

app.get(
  '/api/app/version',
  rateLimit({
    windowMs: 60_000,
    max: 120
  }),
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
            SELECT
              latest_version,
              minimum_version,
              force_update,
              download_url,
              update_message,
              updated_at
            FROM app_version_config
            WHERE id = 1
            LIMIT 1
          `
        );

      const config =
        result.rows[0];

      if (!config) {

        return res
          .status(503)
          .json({
            ok: false,
            error:
              'Version configuration unavailable'
          });
      }

      const currentRaw =
        String(
          req.query.current || ''
        )
          .trim();

      let updateAvailable =
        null;

      let blocked =
        null;

      if (currentRaw) {

        const current =
          parseAppVersion(
            currentRaw
          );

        if (!current) {

          return res
            .status(400)
            .json({
              ok: false,
              error:
                'Invalid current version. Use x.y.z, for example 1.0.0'
            });
        }

        const latestComparison =
          compareAppVersions(
            current.version,
            config.latest_version
          );

        const minimumComparison =
          compareAppVersions(
            current.version,
            config.minimum_version
          );

        updateAvailable =
          latestComparison < 0;

        blocked =
          Boolean(
            config.force_update &&
            minimumComparison < 0
          );
      }

      res.json({
        ok: true,
        latestVersion:
          config.latest_version,
        minimumVersion:
          config.minimum_version,
        forceUpdate:
          Boolean(
            config.force_update
          ),
        downloadUrl:
          config.download_url || '',
        message:
          config.update_message || '',
        updateAvailable,
        blocked,
        updatedAt:
          config.updated_at,
        serverTime:
          nowIso()
      });

    } catch (error) {

      console.error(
        'App version check error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);


/*
 * ---------------------------------------------------------
 * ADMIN APP VERSION
 * ---------------------------------------------------------
 */

app.get(
  '/api/admin/app-version',
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
            SELECT
              latest_version,
              minimum_version,
              force_update,
              download_url,
              update_message,
              updated_at
            FROM app_version_config
            WHERE id = 1
            LIMIT 1
          `
        );

      const config =
        result.rows[0];

      if (!config) {

        return res
          .status(404)
          .json({
            ok: false,
            error:
              'Version configuration not found'
          });
      }

      res.json({
        ok: true,
        latestVersion:
          config.latest_version,
        minimumVersion:
          config.minimum_version,
        forceUpdate:
          Boolean(
            config.force_update
          ),
        downloadUrl:
          config.download_url || '',
        message:
          config.update_message || '',
        updatedAt:
          config.updated_at
      });

    } catch (error) {

      console.error(
        'Admin app version read error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);


app.put(
  '/api/admin/app-version',
  requireAdmin,
  async (req, res) => {

    try {

      const latest =
        parseAppVersion(
          req.body.latestVersion
        );

      const minimum =
        parseAppVersion(
          req.body.minimumVersion
        );

      if (!latest || !minimum) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              'Las versiones deben usar el formato x.y.z, por ejemplo 1.0.1'
          });
      }

      if (
        compareAppVersions(
          minimum.version,
          latest.version
        ) > 0
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              'La versión mínima no puede ser mayor que la última versión'
          });
      }

      const forceUpdate =
        req.body.forceUpdate === true;

      const downloadUrl =
        normalizeDownloadUrl(
          req.body.downloadUrl
        );

      if (downloadUrl === null) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              'El enlace de descarga debe ser http:// o https://'
          });
      }

      const message =
        String(
          req.body.message || ''
        )
          .trim();

      if (message.length > 500) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              'El mensaje no puede superar 500 caracteres'
          });
      }

      const finalMessage =
        message ||
        'Esta versión de XITFORGE ya no está disponible. Descarga la nueva versión para continuar.';

      const result =
        await pool.query(
          `
            UPDATE app_version_config
            SET
              latest_version = $1,
              minimum_version = $2,
              force_update = $3,
              download_url = $4,
              update_message = $5,
              updated_at = NOW()
            WHERE id = 1
            RETURNING
              latest_version,
              minimum_version,
              force_update,
              download_url,
              update_message,
              updated_at
          `,
          [
            latest.version,
            minimum.version,
            forceUpdate,
            downloadUrl,
            finalMessage
          ]
        );

      const config =
        result.rows[0];

      res.json({
        ok: true,
        latestVersion:
          config.latest_version,
        minimumVersion:
          config.minimum_version,
        forceUpdate:
          Boolean(
            config.force_update
          ),
        downloadUrl:
          config.download_url || '',
        message:
          config.update_message || '',
        updatedAt:
          config.updated_at
      });

    } catch (error) {

      console.error(
        'Admin app version update error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);


/*
 * ---------------------------------------------------------
 * LICENSE VALIDATION
 *
 * deviceId = identifierForVendor
 *
 * Only SHA-256(deviceId) is stored.
 * ---------------------------------------------------------
 */

app.post(
  '/api/license/validate',
  rateLimit({
    windowMs: 60_000,
    max: 60
  }),
  async (req, res) => {

    try {

      const key =
        normalizeKey(
          req.body.key
        );

      const deviceId =
        String(
          req.body.deviceId ||
          ''
        ).trim();

      if (
        !isValidKeyFormat(key)
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            valid: false,
            reason:
              'invalid_format'
          });
      }

      if (
        deviceId.length < 8 ||
        deviceId.length > 256
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            valid: false,
            reason:
              'invalid_device'
          });
      }

      const license =
        await getLicenseByHash(
          hashValue(key)
        );

      if (!license) {

        return res.json({
          ok: true,
          valid: false,
          reason:
            'not_found'
        });
      }

      if (
        license.status !== 'active' &&
        license.status !== 'new'
      ) {

        return res.json({
          ok: true,
          valid: false,
          reason:
            'revoked'
        });
      }

      const activeLicense =
        await activateLicenseOnFirstUse(
          license
        );

      if (
        isExpired(
          activeLicense.expires_at
        )
      ) {

        return res.json({
          ok: true,
          valid: false,
          reason:
            'expired',
          expiresAt:
            activeLicense.expires_at
        });
      }

      const deviceHash =
        hashValue(deviceId);

      /*
       * Is this exact device already
       * linked to this license?
       */

      const existing =
        await pool.query(
          `
            SELECT
              id,
              activated_at,
              last_seen_at
            FROM activations
            WHERE license_id = $1
              AND device_hash = $2
            LIMIT 1
          `,
          [
            activeLicense.id,
            deviceHash
          ]
        );

      if (
        existing.rows.length > 0
      ) {

        await pool.query(
          `
            UPDATE activations
            SET last_seen_at = $1
            WHERE id = $2
          `,
          [
            nowIso(),
            existing.rows[0].id
          ]
        );

        return res.json({
          ok: true,
          valid: true,
          expiresAt:
            activeLicense.expires_at,
          keyPrefix:
            activeLicense.key_prefix
        });
      }

      /*
       * Is another device already
       * using this key?
       */

      const activationCount =
        await getActivationCount(
          activeLicense.id
        );

      if (
        activationCount >=
        activeLicense.device_limit
      ) {

        return res.json({
          ok: true,
          valid: false,
          reason:
            'device_limit'
        });
      }

      const timestamp =
        nowIso();

      await pool.query(
        `
          INSERT INTO activations
            (
              license_id,
              device_hash,
              activated_at,
              last_seen_at
            )
          VALUES
            ($1, $2, $3, $4)
        `,
        [
          activeLicense.id,
          deviceHash,
          timestamp,
          timestamp
        ]
      );

      return res.json({
        ok: true,
        valid: true,
        expiresAt:
          activeLicense.expires_at,
        keyPrefix:
          activeLicense.key_prefix
      });

    } catch (error) {

      console.error(
        'License validation error:',
        error
      );

      return res
        .status(500)
        .json({
          ok: false,
          valid: false,
          reason:
            'server_error'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * ADMIN LOGIN
 * ---------------------------------------------------------
 */

app.post(
  '/api/admin/login',
  rateLimit({
    windowMs:
      10 * 60_000,
    max: 10
  }),
  (req, res) => {

    const password =
      String(
        req.body.password ||
        ''
      );

    const supplied =
      Buffer.from(
        password
      );

    const expected =
      Buffer.from(
        ADMIN_PASSWORD ||
        ''
      );

    const passwordMatches =
      supplied.length ===
        expected.length &&
      crypto.timingSafeEqual(
        supplied,
        expected
      );

    if (!passwordMatches) {

      return res
        .status(401)
        .json({
          ok: false,
          error:
            'Invalid password'
        });
    }

    const token =
      signAdminToken({
        role: 'admin',
        exp:
          Date.now() +
          8 * 60 * 60 * 1000
      });

    res.json({
      ok: true,
      token
    });
  }
);

/*
 * ---------------------------------------------------------
 * LIST LICENSES
 * ---------------------------------------------------------
 */

app.get(
  '/api/admin/licenses',
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
            SELECT
              l.id,
              l.key_prefix,
              l.key_last4,
              l.status,
              l.expires_at,
              l.duration_days,
              l.duration_seconds,
              l.first_used_at,
              l.device_limit,
              l.note,
              l.created_at,
              l.updated_at,
              (
                SELECT COUNT(*)::int
                FROM activations a
                WHERE a.license_id = l.id
              ) AS devices
            FROM licenses l
            ORDER BY l.id DESC
          `
        );

      res.json({
        ok: true,
        licenses:
          result.rows
      });

    } catch (error) {

      console.error(
        'List licenses error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * CREATE LICENSE - V2
 *
 * Ya no se generan permanentes.
 * durationDays puede ser cualquier entero entre 1 y 36500.
 * ---------------------------------------------------------
 */

app.post(
  '/api/admin/licenses',
  requireAdmin,
  async (req, res) => {

    try {

      const durationDays =
        Number(
          req.body.durationDays
        );

      const deviceLimit =
        Number(
          req.body.deviceLimit
        );

      const note =
        String(
          req.body.note || ''
        )
          .trim()
          .slice(0, 120);

      if (
        !Number.isInteger(durationDays) ||
        durationDays < 1 ||
        durationDays > 36500
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              'Los días deben ser un número entero entre 1 y 36500'
          });
      }

      if (
        !Number.isInteger(deviceLimit) ||
        deviceLimit < 1 ||
        deviceLimit > 100
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              'El límite de dispositivos debe estar entre 1 y 100'
          });
      }

      const key =
        generateKey();

      const normalized =
        normalizeKey(key);

      const timestamp =
        nowIso();

      /*
       * El tiempo empieza en el primer uso, no al crear la key.
       */
      const expiresAt =
        null;

      const result =
        await pool.query(
          `
            INSERT INTO licenses
              (
                key_hash,
                key_prefix,
                key_last4,
                status,
                expires_at,
                duration_days,
                first_used_at,
                device_limit,
                note,
                created_at,
                updated_at
              )
            VALUES
              (
                $1,
                $2,
                $3,
                'new',
                NULL,
                $4,
                NULL,
                $5,
                $6,
                $7,
                $8
              )
            RETURNING id
          `,
          [
            hashValue(normalized),
            normalized.slice(0, 9),
            normalized.slice(-4),
            durationDays,
            deviceLimit,
            note,
            timestamp,
            timestamp
          ]
        );

      res
        .status(201)
        .json({
          ok: true,
          key: normalized,
          status: 'new',
          expiresAt: null,
          durationDays,
          deviceLimit,
          note,
          createdAt:
            timestamp,
          id:
            result.rows[0].id
        });

    } catch (error) {

      console.error(
        'Create license error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * REVOKE
 * ---------------------------------------------------------
 */

app.post(
  '/api/admin/licenses/:id/revoke',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const result =
        await pool.query(
          `
            UPDATE licenses
            SET
              status = 'revoked',
              updated_at = $1
            WHERE id = $2
          `,
          [
            nowIso(),
            id
          ]
        );

      if (
        result.rowCount !== 1
      ) {

        return res
          .status(404)
          .json({
            ok: false,
            error:
              'License not found'
          });
      }

      res.json({
        ok: true
      });

    } catch (error) {

      console.error(
        'Revoke license error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * REACTIVATE
 * ---------------------------------------------------------
 */

app.post(
  '/api/admin/licenses/:id/reactivate',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const result =
        await pool.query(
          `
            SELECT
              expires_at,
              duration_days,
              duration_seconds,
              first_used_at
            FROM licenses
            WHERE id = $1
            LIMIT 1
          `,
          [id]
        );

      if (
        result.rows.length === 0
      ) {

        return res
          .status(404)
          .json({
            ok: false,
            error:
              'License not found'
          });
      }

      if (
        isExpired(
          result.rows[0].expires_at
        )
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              'Cannot reactivate an expired license without extending it'
          });
      }

      await pool.query(
        `
          UPDATE licenses
          SET
            status =
              CASE
                WHEN expires_at IS NULL
                 AND first_used_at IS NULL
                 AND duration_days IS NOT NULL
                THEN 'new'
                ELSE 'active'
              END,
            updated_at = $1
          WHERE id = $2
        `,
        [
          nowIso(),
          id
        ]
      );

      res.json({
        ok: true
      });

    } catch (error) {

      console.error(
        'Reactivate license error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * EXTEND
 * ---------------------------------------------------------
 */

app.post(
  '/api/admin/licenses/:id/extend',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const days =
        Number(
          req.body.days
        );

      if (
        !Number.isInteger(days) ||
        days < 1 ||
        days > 36500
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              'days must be an integer between 1 and 36500'
          });
      }

      const result =
        await pool.query(
          `
            SELECT
              expires_at,
              duration_days,
              duration_seconds,
              first_used_at
            FROM licenses
            WHERE id = $1
            LIMIT 1
          `,
          [id]
        );

      if (
        result.rows.length === 0
      ) {

        return res
          .status(404)
          .json({
            ok: false,
            error:
              'License not found'
          });
      }

      const row =
        result.rows[0];

      // Preserve the remaining duration of an unused hourly license.
      if (!row.expires_at && !row.first_used_at && row.duration_seconds != null) {
        const updated = await pool.query(`
          UPDATE licenses SET duration_seconds = duration_seconds + $1, updated_at = $2
          WHERE id = $3 RETURNING duration_seconds
        `, [days * 86400, nowIso(), id]);
        return res.json({ ok: true, expiresAt: null,
          durationSeconds: Number(updated.rows[0].duration_seconds), startsOnFirstUse: true });
      }

      const neverUsed =
        !row.expires_at &&
        !row.first_used_at &&
        Number.isInteger(
          Number(row.duration_days)
        );

      if (neverUsed) {

        const newDurationDays =
          Number(row.duration_days) +
          days;

        await pool.query(
          `
            UPDATE licenses
            SET
              duration_days = $1,
              updated_at = $2
            WHERE id = $3
          `,
          [
            newDurationDays,
            nowIso(),
            id
          ]
        );

        return res.json({
          ok: true,
          expiresAt: null,
          durationDays:
            newDurationDays,
          startsOnFirstUse:
            true
        });
      }

      const currentExpiration =
        row.expires_at;

      const base =
        currentExpiration &&
        !isExpired(
          currentExpiration
        )
          ? new Date(
              currentExpiration
            ).getTime()
          : Date.now();

      const expiresAt =
        new Date(
          base +
          days *
            24 *
            60 *
            60 *
            1000
        ).toISOString();

      await pool.query(
        `
          UPDATE licenses
          SET
            expires_at = $1,
            updated_at = $2
          WHERE id = $3
        `,
        [
          expiresAt,
          nowIso(),
          id
        ]
      );

      res.json({
        ok: true,
        expiresAt,
        startsOnFirstUse:
          false
      });

    } catch (error) {

      console.error(
        'Extend license error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * REPLACE KEY
 *
 * Genera una key nueva sin cambiar vencimiento, cliente,
 * límite de dispositivos ni estado. La key anterior deja de
 * funcionar inmediatamente y se liberan los dispositivos.
 * ---------------------------------------------------------
 */

app.post(
  '/api/admin/licenses/:id/replace',
  requireAdmin,
  async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({ ok: false, error: 'ID inválido' });
    }

    let client = null;

    try {
      client = await pool.connect();
      await client.query('BEGIN');

      const current = await client.query(`
        SELECT
          id, status, expires_at, duration_days, first_used_at, device_limit, note
        FROM licenses
        WHERE id = $1
        FOR UPDATE
      `, [id]);

      if (current.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ ok: false, error: 'License not found' });
      }

      let normalized = '';
      let keyHash = '';

      for (let attempt = 0; attempt < 10; attempt += 1) {
        normalized = normalizeKey(generateKey());
        keyHash = hashValue(normalized);

        const collision = await client.query(
          'SELECT 1 FROM licenses WHERE key_hash = $1 AND id <> $2 LIMIT 1',
          [keyHash, id]
        );

        if (collision.rows.length === 0) {
          break;
        }

        normalized = '';
      }

      if (!normalized) {
        throw new Error('Could not generate a unique replacement key');
      }

      const updated = await client.query(`
        UPDATE licenses
        SET
          key_hash = $1,
          key_prefix = $2,
          key_last4 = $3,
          updated_at = $4
        WHERE id = $5
        RETURNING
          id, status, expires_at, duration_days, first_used_at, device_limit, note, updated_at
      `, [
        keyHash,
        normalized.slice(0, 9),
        normalized.slice(-4),
        nowIso(),
        id
      ]);

      await client.query(
        'DELETE FROM activations WHERE license_id = $1',
        [id]
      );

      await client.query('COMMIT');

      res.json({
        ok: true,
        key: normalized,
        license: updated.rows[0],
        devicesReset: true
      });
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch {}
      console.error('Replace license key error:', error);
      res.status(500).json({ ok: false, error: 'Database error' });
    } finally {
      if (client) {
        client.release();
      }
    }
  }
);

/*
 * ---------------------------------------------------------
 * UPDATE LICENSE - V2
 * ---------------------------------------------------------
 */

app.patch(
  '/api/admin/licenses/:id',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isSafeInteger(id) ||
        id < 1
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error: 'ID inválido'
          });
      }

      const deviceLimit =
        Number(
          req.body.deviceLimit
        );

      const note =
        String(
          req.body.note || ''
        )
          .trim()
          .slice(0, 120);

      if (
        !Number.isInteger(deviceLimit) ||
        deviceLimit < 1 ||
        deviceLimit > 100
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              'El límite de dispositivos debe estar entre 1 y 100'
          });
      }

      const result =
        await pool.query(
          `
            UPDATE licenses
            SET
              device_limit = $1,
              note = $2,
              updated_at = $3
            WHERE id = $4
            RETURNING
              id,
              device_limit,
              note,
              updated_at
          `,
          [
            deviceLimit,
            note,
            nowIso(),
            id
          ]
        );

      if (
        result.rowCount !== 1
      ) {
        return res
          .status(404)
          .json({
            ok: false,
            error: 'License not found'
          });
      }

      res.json({
        ok: true,
        license:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        'Update license error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * VIEW ACTIVATIONS - V2
 * ---------------------------------------------------------
 */

app.get(
  '/api/admin/licenses/:id/activations',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const exists =
        await pool.query(
          `
            SELECT id
            FROM licenses
            WHERE id = $1
            LIMIT 1
          `,
          [id]
        );

      if (
        exists.rows.length === 0
      ) {
        return res
          .status(404)
          .json({
            ok: false,
            error: 'License not found'
          });
      }

      const result =
        await pool.query(
          `
            SELECT
              id,
              UPPER(
                SUBSTRING(
                  device_hash
                  FROM 1 FOR 8
                )
              ) AS device_code,
              activated_at,
              last_seen_at
            FROM activations
            WHERE license_id = $1
            ORDER BY last_seen_at DESC
          `,
          [id]
        );

      res.json({
        ok: true,
        activations:
          result.rows
      });

    } catch (error) {

      console.error(
        'View activations error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * RESET ALL DEVICES
 * ---------------------------------------------------------
 */

app.delete(
  '/api/admin/licenses/:id/activations',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const license =
        await pool.query(
          `
            SELECT id
            FROM licenses
            WHERE id = $1
            LIMIT 1
          `,
          [id]
        );

      if (
        license.rows.length === 0
      ) {
        return res
          .status(404)
          .json({
            ok: false,
            error: 'License not found'
          });
      }

      const result =
        await pool.query(
          `
            DELETE FROM activations
            WHERE license_id = $1
          `,
          [id]
        );

      res.json({
        ok: true,
        removed:
          result.rowCount
      });

    } catch (error) {

      console.error(
        'Reset devices error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * REMOVE ONE DEVICE
 * ---------------------------------------------------------
 */

app.delete(
  '/api/admin/licenses/:id/activations/:activationId',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const activationId =
        Number(
          req.params.activationId
        );

      const result =
        await pool.query(
          `
            DELETE FROM activations
            WHERE id = $1
              AND license_id = $2
          `,
          [
            activationId,
            id
          ]
        );

      if (
        result.rowCount !== 1
      ) {
        return res
          .status(404)
          .json({
            ok: false,
            error:
              'Dispositivo no encontrado'
          });
      }

      res.json({
        ok: true
      });

    } catch (error) {

      console.error(
        'Remove device error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * DELETE LICENSE
 * ---------------------------------------------------------
 */

app.delete(
  '/api/admin/licenses/:id',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const result =
        await pool.query(
          `
            DELETE FROM licenses
            WHERE id = $1
          `,
          [id]
        );

      if (
        result.rowCount !== 1
      ) {
        return res
          .status(404)
          .json({
            ok: false,
            error:
              'License not found'
          });
      }

      res.json({
        ok: true
      });

    } catch (error) {

      console.error(
        'Delete license error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          error:
            'Database error'
        });
    }
  }
);

/*
 * ---------------------------------------------------------
 * DYNAMIC APP OPTIONS
 * ---------------------------------------------------------
 *
 * Esto conecta tu panel con options-routes.js.
 *
 * El módulo crea:
 *
 *   app_options
 *
 * y las rutas:
 *
 *   /api/admin/options
 *   /api/admin/options/:id
 *   /api/admin/options/:id/status
 *   /api/admin/options/:id/file
 *
 *   /api/app/options
 *   /api/app/options/:id/file
 *
 * Las rutas administrativas requieren el mismo
 * Bearer token del panel de licencias.
 * ---------------------------------------------------------
 */

let optionsDatabaseReady = null;

const freeKeysModule = registerFreeKeyRoutes({
  app, pool, rateLimit, generateKey, normalizeKey, hashValue,
  secret: process.env.FREE_KEYS_SECRET || ADMIN_TOKEN_SECRET
});

try {

  const optionsModule =
    registerOptionsRoutes({
      app,
      pool,
      requireAdmin
    });

  optionsDatabaseReady =
    optionsModule.ensureTable();

} catch (error) {

  console.error(
    'Failed to register app options routes:',
    error
  );

  process.exit(1);
}

/*
 * ---------------------------------------------------------
 * STATIC PANEL
 * ---------------------------------------------------------
 */

app.use(
  express.static(
    path.join(
      __dirname,
      'public'
    )
  )
);

/*
 * ---------------------------------------------------------
 * START SERVER
 * ---------------------------------------------------------
 */

async function startServer() {

  try {

    await initializeDatabase();
    await freeKeysModule.ensureTables();

    /*
     * Esperar también a que la tabla
     * de opciones esté creada.
     */

    await optionsDatabaseReady;

    app.listen(
      PORT,
      () => {

        console.log(
          `XITFORGE License Server running on ${PUBLIC_BASE_URL}`
        );

        console.log(
          'XITFORGE App Options API ready.'
        );


        console.log(
          'XITFORGE App Version API ready.'
        );

      }
    );

  } catch (error) {

    console.error(
      'Failed to initialize server:',
      error
    );

    process.exit(1);
  }
}

startServer();
