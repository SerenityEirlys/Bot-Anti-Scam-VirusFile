import { SlashCommandBuilder, PermissionFlagsBits } from 'discord.js'

export const data = new SlashCommandBuilder()
  .setName('dashboard')
  .setDescription('Mở bảng điều khiển')

export async function execute(interaction) {
  const url = process.env.PANEL_URL || `http://localhost:${process.env.PORT || 3000}`
  if (!interaction.memberPermissions?.has(PermissionFlagsBits.Administrator)) {
    return interaction.reply({ content: 'Bạn không có quyền sử dụng lệnh này', ephemeral: true })
  }
  return interaction.reply({ content: url, ephemeral: true })
}