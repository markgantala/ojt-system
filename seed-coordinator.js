require('dotenv').config();
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY);

async function seed() {
  const number = process.argv[2] || 'COORD-001';
  const name = process.argv[3] || 'OJT Coordinator';
  const password = process.argv[4] || 'admin123';

  const { data: existing } = await supabase
    .from('profiles').select('id').eq('student_number', number).single();
  if (existing) { console.log('⚠️ Coordinator already exists'); return; }

  const hash = await bcrypt.hash(password, 10);
  const { error } = await supabase.from('profiles').insert({
    student_number: number,
    password_hash: hash,
    full_name: name,
    role: 'coordinator',
    campus: 'Main',
  });

  if (error) { console.error('❌', error.message); process.exit(1); }

  console.log('\n✅ Coordinator created!');
  console.log('   Number  :', number);
  console.log('   Password:', password);
  console.log('   (Login at /index.html)\n');
}

seed();