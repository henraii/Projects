import type { APIRoute } from 'astro';
import { connectToMongo } from '../../lib/mongodb';
import bcrypt from 'bcryptjs'; // Use bcryptjs

export const POST: APIRoute = async ({ request }) => {
  try {
    const { email, password } = await request.json();
    const db = await connectToMongo();
    const existingUser = await db.collection('users').findOne({ email });

    if (existingUser) {
      return new Response(JSON.stringify({ error: 'User already exists' }), { status: 400 });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('users').insertOne({ email, password: hashedPassword });
    return new Response(JSON.stringify({ message: 'User created' }), { status: 201 });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Server error' }), { status: 500 });
  }
};