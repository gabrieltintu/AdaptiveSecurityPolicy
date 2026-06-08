import { definePreset } from '@primeuix/themes';
import Aura from '@primeuix/themes/aura';

export const AspPreset = definePreset(Aura, {
  semantic: {
    primary: {
      50:  '#faf5ff',
      100: '#f3e8ff',
      200: '#e9d5ff',
      300: '#d8b4fe',
      400: '#c084fc',
      500: '#a855f7',
      600: '#9333ea',
      700: '#7c3aed',
      800: '#6b21a8',
      900: '#581c87',
      950: '#3b0764'
    },
    colorScheme: {
      dark: {
        surface: {
          0:   '#ffffff',
          50:  '#f6f2fb',
          100: '#e9e0f4',
          200: '#cdbce4',
          300: '#a888c9',
          400: '#7e57a8',
          500: '#5b3a85',
          600: '#472d6b',
          700: '#34204f',
          800: '#22153a',
          900: '#160a26',
          950: '#0d0518'
        },
        primary: {
          color: '{primary.400}',
          contrastColor: '#1a0b2e',
          hoverColor: '{primary.300}',
          activeColor: '{primary.500}'
        },
        highlight: {
          background: 'rgba(168, 85, 247, 0.18)',
          focusBackground: 'rgba(168, 85, 247, 0.28)',
          color: '#f3e8ff',
          focusColor: '#f3e8ff'
        }
      }
    }
  }
});
