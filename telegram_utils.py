from aiogram import Bot, types


def sanitize_newlines(text: str) -> str:
    """Replace HTML <br> with real newlines."""
    return (text or "").replace("<br/>", "\n").replace("<br />", "\n").replace("<br>", "\n")


async def safe_send_message(bot: Bot, chat_id: int, text: str, **kwargs) -> None:
    """Send a message and ignore telegram API errors."""
    try:
        await bot.send_message(chat_id, sanitize_newlines(text), **kwargs)
    except Exception:
        pass


async def safe_send_photo(
    bot: Bot, chat_id: int, photo: str, caption: str | None = None, **kwargs
) -> None:
    """Send a photo and ignore telegram API errors."""
    try:
        await bot.send_photo(
            chat_id,
            photo=photo,
            caption=sanitize_newlines(caption) if caption else None,
            **kwargs,
        )
    except Exception:
        pass


async def safe_answer(message: types.Message, text: str, **kwargs) -> None:
    """Reply to a message safely."""
    try:
        await message.answer(sanitize_newlines(text), **kwargs)
    except Exception:
        pass
