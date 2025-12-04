# 🔒 InvisioVault Frontend

> The pretty face of our sneaky file-hiding operation!

## What's This All About?

Welcome to the frontend of InvisioVault! This is where all the magic happens (well, visually at least). Built with React and Vite because we like our builds fast and our code hot-reloading even faster. ⚡

## 🚀 Getting Started (Let's Go!)

### First Time Setup
```bash
npm install
```
Grab a coffee ☕ while npm does its thing.

### Fire It Up!
```bash
npm run dev
```
Boom! 💥 Your dev server should be running at `http://localhost:5173`

### Build for Production
```bash
npm run build
```
Time to get serious. This'll bundle everything up nice and tight.

### Preview Production Build
```bash
npm run preview
```
Wanna see how it'll look in the real world? This is your guy.

## 🎨 What's Inside?

- **React 19** - Because we live on the edge
- **Vite** - Lightning-fast builds (seriously, it's ridiculously fast)
- **Axios** - For talking to our backend buddy
- **CSS that doesn't make you cry** - Black & white theme that's sleek AF

## 📁 Project Structure (Where Everything Lives)

```
src/
├── components/          # All our React components hang out here
│   ├── HideFile.jsx    # Hide files like a ninja 🥷
│   ├── ExtractFile.jsx # Find 'em again
│   ├── Polyglot.jsx    # The shapeshifter
│   └── TutorialModal.jsx # Help for the confused
├── config/             # Configuration stuff
├── App.jsx             # The main stage
├── App.css             # Where the style magic happens
└── main.jsx            # The entry point (it all starts here)
```

## 🛠️ Tech Stack

- **React** - For making things reactive (duh)
- **Vite** - Dev server that goes brrrr
- **ESLint** - Keeps our code from looking like spaghetti

## 💡 Pro Tips

1. **Hot Module Replacement (HMR)** is enabled - save a file and watch it update instantly. It's like magic but real.
2. **ESLint is watching** - it'll yell at you if your code is messy (in a helpful way)
3. **Check the browser console** - it's your friend when things go sideways

## 🐛 Something Broke?

Don't panic! Try these:

1. **Delete `node_modules` and reinstall**
   ```bash
   rm -rf node_modules
   npm install
   ```
   (The classic "turn it off and on again" of web development)

2. **Clear Vite cache**
   ```bash
   rm -rf node_modules/.vite
   ```

3. **Check if the backend is running** - frontend can't do much without it!

4. **Still broken?** Open an issue on GitHub or ping @Rolan

## 🎯 Want to Contribute?

Awesome! Here's what you should know:

- Keep the code clean and readable (future you will thank you)
- Follow the existing style - consistency is king
- Test your changes before pushing (I know, revolutionary idea)
- Write commit messages that actually mean something

## 📚 Learn More

- [React Docs](https://react.dev) - Everything React
- [Vite Docs](https://vite.dev) - For when Vite does something weird
- [InvisioVault Main README](../README.md) - The full story

## 🎉 Fun Facts

- This project uses Vite because webpack config files give us nightmares
- The info button has a little spin animation because why not?
- Every component is crafted with love (and probably too much coffee)

---

Made with ❤️ and probably too many energy drinks by [Rolan](https://rolan-rnr.netlify.app/)

*Remember: With great steganography power comes great responsibility. Use wisely!* 🦸
