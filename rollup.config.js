import typescript from '@rollup/plugin-typescript';
import { nodeResolve } from '@rollup/plugin-node-resolve';
// import commonjs from '@rollup/plugin-commonjs';

export default {
  input: 'src/pico-auth.ts',
  output: [
    {
      file: 'dist/pico-auth.esm.js',
      format: 'es'
    },
    {
      file: 'dist/pico-auth.umd.js',
      format: 'umd',
      name: 'picoAuth',
      // globals: { speakeasy: 'speakeasy', qrcode: 'qrcode', md5:'md5'},
    }
  ],   
  // external:['speakeasy','qrcode','md5'],
  // plugins: [typescript(), nodeResolve()],
  plugins: [
    nodeResolve(), 
    // commonjs(), // for "require()" libraries in auth.js to get "externalized"
    typescript()],
};
