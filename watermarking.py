from PIL import Image, ImageDraw, ImageFont

def add_watermark(image_path, watermark_text, output_image_path):
    try:
        image = Image.open(image_path).convert("RGBA")
        txt = Image.new("RGBA", image.size, (255, 255, 255, 0))
        font_size = min(image.width, image.height) // 10  # Scale font size dynamically
        font = ImageFont.truetype("arial.ttf", font_size)
        draw = ImageDraw.Draw(txt)
        
        # Calculate text size and center position
        bbox = draw.textbbox((0, 0), watermark_text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        position = (
            (image.width - text_width) // 2,  # Center horizontally
            (image.height - text_height) // 2  # Center vertically
        )
        
        # Draw text with reduced opacity (e.g., 64 instead of 128, where 255 is fully opaque)
        draw.text(position, watermark_text, fill=(255, 255, 255, 64), font=font)
        
        watermarked = Image.alpha_composite(image, txt)
        watermarked.save(output_image_path)
        return True
    except Exception as e:
        print(f"Error adding watermark: {e}")
        return False

def remove_watermark(image_path, watermark_text, output_image_path):
    try:
        image = Image.open(image_path).convert("RGBA")
        cleaned_image = image.copy()
        font = ImageFont.truetype("arial.ttf", 40)
        bbox = ImageDraw.Draw(cleaned_image).textbbox((0, 0), watermark_text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        position = (image.width - text_width - 10, image.height - text_height - 10)
        padding = 10
        region = (
            position[0] - padding,
            position[1] - padding,
            position[0] + text_width + padding,
            position[1] + text_height + padding
        )
        if region[0] >= 0 and region[1] >= 0 and region[2] <= image.width and region[3] <= image.height:
            cleaned_image = cleaned_image.crop((0, 0, image.width, region[1]))
        cleaned_image.save(output_image_path)
        return True
    except Exception as e:
        print(f"Error removing watermark: {e}")
        return False