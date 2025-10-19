import type { APIRoute } from 'astro';
import { connectToMongo } from '../../lib/mongodb';
import bcrypt from 'bcryptjs'; // Use bcryptjs
import jwt from 'jsonwebtoken';

export const POST: APIRoute = async ({ request }) => {
  try {
    const { email, password } = await request.json();
    const db = await connectToMongo();
    const user = await db.collection('users').findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401 });
    }

    const token = jwt.sign({ userId: user._id.toString() }, import.meta.env.JWT_SECRET, { expiresIn: '1h' });
    return new Response(JSON.stringify({ token }), { status: 200 });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Server error' }), { status: 500 });
  }
};