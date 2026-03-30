import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useThemeStore = defineStore('theme', () => {
  const isDark = ref(localStorage.getItem('theme') === 'dark')

  function toggleTheme() {
    isDark.value = !isDark.value
    localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
    updateTheme()
  }

  function setTheme(dark: boolean) {
    isDark.value = dark
    localStorage.setItem('theme', dark ? 'dark' : 'light')
    updateTheme()
  }

  function updateTheme() {
    if (isDark.value) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }

  // Initialize theme on load
  updateTheme()

  return {
    isDark,
    toggleTheme,
    setTheme
  }
})

