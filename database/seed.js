const bcrypt = require('bcryptjs');
const db = require('./db');

const SALT_ROUNDS = 10;

async function seed() {
  console.log('🌱 Seeding database...');

  // ── Default admin user ──
  const existingAdmin = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  if (!existingAdmin) {
    const hash = await bcrypt.hash('changeme123', SALT_ROUNDS);
    db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)').run(
      'admin',
      'admin@cybersec.local',
      hash,
      'admin'
    );
    console.log('  ✓ Created default admin user (admin / changeme123)');
  } else {
    console.log('  ⏭ Admin user already exists');
  }

  // ── Default site stats ──
  const stats = [
    { key: 'clients', value: '300+', label: 'Clients', order: 1 },
    { key: 'satisfaction', value: '99%', label: 'Satisfaction', order: 2 },
    { key: 'revenue', value: '$5M+', label: 'Revenue', order: 3 },
  ];

  const insertStat = db.prepare(`
    INSERT OR IGNORE INTO site_stats (stat_key, stat_value, stat_label, display_order)
    VALUES (?, ?, ?, ?)
  `);

  for (const s of stats) {
    const result = insertStat.run(s.key, s.value, s.label, s.order);
    if (result.changes > 0) {
      console.log(`  ✓ Seeded stat: ${s.value} ${s.label}`);
    } else {
      console.log(`  ⏭ Stat "${s.key}" already exists`);
    }
  }

  console.log('✅ Seed complete.');
}

seed().catch(err => {
  console.error('Seed failed:', err);
  process.exit(1);
});
